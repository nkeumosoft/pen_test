from infrastructure.framework import db
from infrastructure.framework.models import Website
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import WebsiteEntity


def update_website(website_entity: WebsiteEntity) -> WebsiteEntity:
    """Update a website."""

    website_repo = WebsiteRepository(db, Website)

    return website_repo.update(website_entity)


def create_website(website_entity: WebsiteEntity)-> WebsiteEntity:
    website_repo = WebsiteRepository(db, Website)

    return website_repo.create(website_entity)
