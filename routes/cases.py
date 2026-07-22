from fastapi import APIRouter, HTTPException, Query

from models.case_models import CaseCreateRequest, CaseNoteCreateRequest
from storage import case_store


router = APIRouter()


@router.get("/cases")
def list_saved_cases(limit: int = Query(25, ge=1, le=100)):
    return case_store.list_cases(limit)


@router.post("/cases", status_code=201)
def save_case(payload: CaseCreateRequest):
    results = [result.model_dump(mode="json") for result in payload.results]
    return case_store.create_case(payload.title, payload.tags, payload.note, results)


@router.get("/cases/{case_id}")
def get_saved_case(case_id: int):
    case = case_store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases/{case_id}/notes")
def add_case_note(case_id: int, payload: CaseNoteCreateRequest):
    case = case_store.add_note(case_id, payload.body)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case
