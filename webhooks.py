import hashlib
import hmac
from uuid import UUID

import structlog
from fastapi import APIRouter, Header, HTTPException, Request, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.organization import Organization
from app.models.project import Project
from app.models.user import User
from app.models.webhook_event import WebhookEvent

logger = structlog.get_logger()
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/github")
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_hub_signature_256: str = Header(default=""),
    x_github_event: str = Header(default=""),
    x_github_delivery: str = Header(default=""),
):
    """Receive and process GitHub webhook events."""
    body = await request.body()

    # 1. Validate signature (skip in development if signature missing — smee proxy can alter body)
    if not settings.GITHUB_WEBHOOK_SECRET:
        logger.warning("webhook_secret_not_configured")
    elif x_hub_signature_256:
        if not _verify_signature(body, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
            if settings.is_production:
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
            logger.warning("webhook_signature_mismatch_dev", event=x_github_event)
    elif settings.is_production:
        raise HTTPException(status_code=401, detail="Missing webhook signature")

    # 2. Require delivery ID
    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Delivery header")

    # 3. Check idempotency
    existing = await db.execute(
        select(WebhookEvent).where(WebhookEvent.github_delivery_id == UUID(x_github_delivery))
    )
    if existing.scalar_one_or_none():
        logger.info("webhook_duplicate", delivery_id=x_github_delivery)
        return {"status": "already_processed"}

    payload = await request.json()

    # 4. Create webhook event record
    webhook_event = WebhookEvent(
        github_delivery_id=UUID(x_github_delivery),
        event_type=x_github_event,
        action=payload.get("action"),
        payload_summary={
            "sender": payload.get("sender", {}).get("login"),
            "repo": payload.get("repository", {}).get("full_name"),
        },
    )
    db.add(webhook_event)
    await db.flush()

    # 4. Route by event type
    try:
        if x_github_event == "pull_request":
            await _handle_pull_request(db, payload, webhook_event)
        elif x_github_event == "installation":
            await _handle_installation(db, payload, webhook_event)
        elif x_github_event == "installation_repositories":
            await _handle_installation_repos(db, payload, webhook_event)
        else:
            webhook_event.status = "skipped"
            logger.info("webhook_unhandled_event", event_type=x_github_event)
    except Exception as e:
        webhook_event.status = "failed"
        webhook_event.error_message = str(e)
        logger.error("webhook_processing_error", event_type=x_github_event, error=str(e))

    await db.flush()
    return {"status": "accepted"}


async def _handle_pull_request(db: AsyncSession, payload: dict, webhook_event: WebhookEvent):
    """Handle pull_request webhook events."""
    action = payload.get("action")

    # Only process relevant actions
    if action not in ("opened", "synchronize", "reopened"):
        webhook_event.status = "skipped"
        return

    pr_data = payload["pull_request"]
    repo_data = payload["repository"]
    sender = payload["sender"]
    installation = payload.get("installation", {})

    github_repo_id = repo_data["id"]
    pr_number = payload["number"]
    installation_id = installation.get("id")

    webhook_event.github_pr_number = pr_number

    # Look up project
    stmt = select(Project).where(Project.github_repo_id == github_repo_id, Project.deleted_at.is_(None))
    result = await db.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        webhook_event.status = "skipped"
        logger.info("webhook_project_not_found", github_repo_id=github_repo_id)
        return

    webhook_event.org_id = project.org_id
    webhook_event.project_id = project.id

    # Find or create user for PR author
    github_user_id = sender["id"]
    stmt = select(User).where(User.github_user_id == github_user_id, User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Auto-create as developer in the project's org
        user = User(
            org_id=project.org_id,
            email=f"{sender['login']}@github.noemail",
            name=sender["login"],
            github_user_id=github_user_id,
            github_username=sender["login"],
            avatar_url=sender.get("avatar_url"),
            role="developer",
        )
        db.add(user)
        await db.flush()

    # Enqueue Celery review task
    from app.workers.review_task import process_review

    process_review.delay(
        installation_id=installation_id,
        repo_full_name=repo_data["full_name"],
        pr_number=pr_number,
        pr_title=pr_data.get("title", ""),
        pr_url=pr_data.get("html_url", ""),
        base_branch=pr_data.get("base", {}).get("ref", ""),
        head_branch=pr_data.get("head", {}).get("ref", ""),
        user_id=str(user.id),
        project_id=str(project.id),
        org_id=str(project.org_id),
        review_depth=project.review_depth,
    )

    webhook_event.status = "processing"
    logger.info(
        "review_task_enqueued",
        project=repo_data["full_name"],
        pr_number=pr_number,
        depth=project.review_depth,
    )


async def _handle_installation(db: AsyncSession, payload: dict, webhook_event: WebhookEvent):
    """Handle installation.created / installation.deleted events."""
    action = payload.get("action")
    installation = payload["installation"]
    account = installation["account"]

    if action == "created":
        # Create or update organization — try github_org_id first, then slug match
        stmt = select(Organization).where(Organization.github_org_id == account["id"])
        result = await db.execute(stmt)
        org = result.scalar_one_or_none()

        if not org:
            # Try matching by slug (personal accounts created during OAuth)
            stmt = select(Organization).where(
                Organization.slug == account["login"].lower(),
                Organization.deleted_at.is_(None),
            )
            result = await db.execute(stmt)
            org = result.scalar_one_or_none()

        if not org:
            org = Organization(
                name=account["login"],
                slug=account["login"].lower(),
                github_org_id=account["id"],
                github_installation_id=installation["id"],
            )
            db.add(org)
        else:
            org.github_org_id = account["id"]
            org.github_installation_id = installation["id"]
            org.deleted_at = None  # Reactivate if was soft-deleted

        await db.flush()
        webhook_event.org_id = org.id
        webhook_event.status = "processed"
        logger.info("installation_created", org_slug=org.slug, installation_id=installation["id"])

    elif action == "deleted":
        stmt = select(Organization).where(Organization.github_installation_id == installation["id"])
        result = await db.execute(stmt)
        org = result.scalar_one_or_none()

        if org:
            from datetime import datetime
            org.deleted_at = datetime.utcnow()
            webhook_event.org_id = org.id
            logger.info("installation_deleted", org_slug=org.slug)

        webhook_event.status = "processed"
    else:
        webhook_event.status = "skipped"


async def _handle_installation_repos(db: AsyncSession, payload: dict, webhook_event: WebhookEvent):
    """Handle installation_repositories.added / removed events."""
    action = payload.get("action")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")

    # Find the org by installation_id, or fall back to account slug
    stmt = select(Organization).where(Organization.github_installation_id == installation_id)
    result = await db.execute(stmt)
    org = result.scalar_one_or_none()

    if not org:
        # Fall back: match by account login (personal accounts)
        account = installation.get("account", {})
        login = account.get("login", "")
        if login:
            stmt = select(Organization).where(
                Organization.slug == login.lower(),
                Organization.deleted_at.is_(None),
            )
            result = await db.execute(stmt)
            org = result.scalar_one_or_none()
            if org:
                # Link the installation to this org
                org.github_installation_id = installation_id
                org.github_org_id = account.get("id")
                await db.flush()

    if not org:
        webhook_event.status = "skipped"
        return

    webhook_event.org_id = org.id

    if action == "added":
        for repo in payload.get("repositories_added", []):
            # Check if project already exists
            stmt = select(Project).where(Project.github_repo_id == repo["id"])
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                project = Project(
                    org_id=org.id,
                    name=repo["name"],
                    github_repo_id=repo["id"],
                    github_repo_full_name=repo["full_name"],
                )
                db.add(project)

    elif action == "removed":
        from datetime import datetime
        for repo in payload.get("repositories_removed", []):
            stmt = select(Project).where(Project.github_repo_id == repo["id"])
            result = await db.execute(stmt)
            project = result.scalar_one_or_none()
            if project:
                project.deleted_at = datetime.utcnow()

    await db.flush()
    webhook_event.status = "processed"
    logger.info("installation_repos_updated", action=action, org_slug=org.slug)
