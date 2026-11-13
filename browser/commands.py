from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Empty(Params): pass
class Create(Params):
    profile_id: str | None = None
    width: int = Field(1280, ge=640, le=1920)
    height: int = Field(800, ge=480, le=1080)
class Navigate(Params):
    url: str = Field(max_length=4096)
    ready_selector: str | None = Field(None, max_length=500)
class Element(Params):
    selector: str = Field(max_length=500)
    approval_id: str | None = None
class Fill(Element):
    text: str = Field(max_length=10000)
class Select(Element):
    value: str = Field(max_length=1000)
class Scroll(Params):
    x: int = Field(0, ge=-5000, le=5000)
    y: int = Field(600, ge=-5000, le=5000)
class Key(Params):
    key: Literal["Tab", "Shift+Tab", "Escape", "ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "PageDown", "PageUp", "Home", "End", "Enter", "Space", "Backspace", "Delete"]
    approval_id: str | None = None
class Tab(Params):
    tab_id: str
class NewTab(Params):
    url: str | None = None
class Screenshot(Params):
    full_page: bool = False
    selector: str | None = Field(None, max_length=500)
class Inspect(Params):
    selector: str = Field("a,button,input,select,textarea,[role=button]", max_length=500)
class Wait(Params):
    selector: str | None = Field(None, max_length=500)
    state: Literal["visible", "hidden", "attached", "detached"] = "visible"
    milliseconds: int = Field(0, ge=0, le=5000)
class Close(Params):
    save_profile: bool = True
class Profile(Params):
    profile_id: str
class Task(Params):
    task_id: str
class File(Element):
    file_id: str
class Download(Element): pass
class Steps(Params):
    description: str = Field(max_length=2000)
    steps: list[dict] = Field(min_length=1, max_length=50)
class Resume(Task): pass
class Approval(Params):
    action: Literal["click", "fill", "type", "select", "press_key", "upload_file", "download_file"]
    params: dict

READ = dict(methods=Empty, status=Empty, sessions=Empty, tabs=Empty, snapshot=Empty,
    screenshot=Screenshot, inspect=Inspect, console=Empty, network=Empty,
    task_status=Task, task_result=Task, usage=Empty, profiles=Empty)
WRITE = dict(create_session=Create, navigate=Navigate, click=Element, fill=Fill, type=Fill,
    select=Select, scroll=Scroll, press_key=Key, switch_tab=Tab, new_tab=NewTab,
    upload_file=File, download_file=Download, wait=Wait, execute_steps=Steps,
    cancel_task=Task, close_session=Close, delete_profile=Profile,
    request_approval=Approval, resume_task=Resume)
SENSITIVE = {"click", "fill", "type", "select", "upload_file", "download_file", "press_key"}


def validate(action, params, write=False):
    model = (WRITE if write else READ).get(action)
    if model is None:
        raise ValueError("unknown_action")
    return model.model_validate(params).model_dump()


def methods():
    return {kind: {a: m.model_json_schema() for a, m in actions.items()}
            for kind, actions in [("browser_read", READ), ("browser_write", WRITE)]}
