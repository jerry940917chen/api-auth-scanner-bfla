from sqlalchemy.orm import Session
from scanner.models import Project
from .base import BaseRepository

class ProjectRepository(BaseRepository[Project]):
    def __init__(self, db: Session):
        super().__init__(db, Project)
