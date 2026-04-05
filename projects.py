from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_org_scope, require_role
from app.models.user import User
from app.schemas.common import APIResponse
from app.schemas.project import ProjectCreate, ProjectResponse, ProjectUpdate
from app.services import billing_service, project_service as proj_svc
from app.utils.audit import log_action

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=APIResponse[list[ProjectResponse]])
async def list_projects(
    org_scope: tuple[User, UUID] = Depends(get_current_org_scope),
    db: AsyncSession = Depends(get_db),
):
    _, org_id = org_scope
    projects = await proj_svc.list_projects(db, org_id)
    return APIResponse(data=[ProjectResponse.model_validate(p) for p in projects])


@router.post("", response_model=APIResponse[ProjectResponse], status_code=201)
async def create_project(
    body: ProjectCreate,
    org_scope: tuple[User, UUID] = Depends(get_current_org_scope),
    _: User = Depends(require_role("lead", "admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    user, org_id = org_scope

    if not await billing_service.can_create_project(org_id):
        raise HTTPException(status_code=403, detail="Plan limit reached for projects")

    project = await proj_svc.create_project(db, org_id, **body.model_dump())
    await log_action(db, org_id, "project.created", "project", project.id, user.id)
    return APIResponse(data=ProjectResponse.model_validate(project))


@router.get("/{project_id}", response_model=APIResponse[ProjectResponse])
async def get_project(
    project_id: UUID,
    org_scope: tuple[User, UUID] = Depends(get_current_org_scope),
    db: AsyncSession = Depends(get_db),
):
    _, org_id = org_scope
    project = await proj_svc.get_project(db, org_id, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return APIResponse(data=ProjectResponse.model_validate(project))


@router.patch("/{project_id}", response_model=APIResponse[ProjectResponse])
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    org_scope: tuple[User, UUID] = Depends(get_current_org_scope),
    _: User = Depends(require_role("lead", "admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    user, org_id = org_scope
    project = await proj_svc.update_project(db, org_id, project_id, **body.model_dump(exclude_none=True))
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    await log_action(db, org_id, "project.updated", "project", project.id, user.id)
    return APIResponse(data=ProjectResponse.model_validate(project))


@router.delete("/{project_id}")
async def delete_project(
    project_id: UUID,
    org_scope: tuple[User, UUID] = Depends(get_current_org_scope),
    _: User = Depends(require_role("admin", "owner")),
    db: AsyncSession = Depends(get_db),
):
    user, org_id = org_scope
    deleted = await proj_svc.delete_project(db, org_id, project_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Project not found")

    await log_action(db, org_id, "project.deleted", "project", project_id, user.id)
    return {"success": True, "data": "Project deactivated"}
