"""Capture actual pixels from the SAME X display served by noVNC.
No second browser and no reconstruction from DOM. Kiosk mode aligns the physical
screen and CSS viewport at device scale 1. Full-page capture explicitly scrolls,
collects real screen tiles and restores the original scroll position.
"""
import asyncio
import io
import math
import mss
from PIL import Image
from .store import Denied

MAX_PIXELS = 16_000_000


def grab(display, width, height):
    with mss.mss(display=display) as screen:
        pixels = screen.grab({"left": 0, "top": 0, "width": width, "height": height})
        return Image.frombytes("RGB", (width, height), pixels.rgb)


def png(image):
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


async def scroll_and_paint(page, x, y):
    # A timer alone can run before Chromium's compositor repaints the X display.
    # Wait through two actual rendering frames after an instantaneous scroll.
    position = await page.evaluate("""async p => {
        window.scrollTo({left:p.x, top:p.y, behavior:'instant'});
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        return {x:scrollX, y:scrollY};
    }""", {"x": x, "y": y})
    await asyncio.sleep(.15)
    return position


async def capture(session, params):
    page = session.page
    viewport = page.viewport_size
    width, height = viewport["width"], viewport["height"]
    display = ":" + str(91 + session.vnc_port - 5901)
    if params.get("selector"):
        box = await page.locator(params["selector"]).bounding_box()
        if not box or box["width"] <= 0 or box["height"] <= 0:
            raise Denied("element_not_visible")
        if box["x"] < 0 or box["y"] < 0 or box["x"]+box["width"] > width or box["y"]+box["height"] > height:
            raise Denied("element_outside_viewport_use_scroll")
        image = await asyncio.to_thread(grab, display, width, height)
        image = image.crop((math.floor(box["x"]), math.floor(box["y"]),
                            math.ceil(box["x"]+box["width"]), math.ceil(box["y"]+box["height"])))
    elif params.get("full_page"):
        size = await page.evaluate("() => ({w:document.documentElement.scrollWidth,h:document.documentElement.scrollHeight,x:scrollX,y:scrollY})")
        if size["w"]*size["h"] > MAX_PIXELS:
            raise Denied("screenshot_too_large_use_element_or_viewport")
        image = Image.new("RGB", (size["w"], size["h"]))
        try:
            for y in range(0, size["h"], height):
                for x in range(0, size["w"], width):
                    position = await scroll_and_paint(page, x, y)
                    tile = await asyncio.to_thread(grab, display, width, height)
                    image.paste(tile, (round(position["x"]), round(position["y"])))
        finally:
            try:
                async with asyncio.timeout(2):
                    await scroll_and_paint(page, size["x"], size["y"])
            except Exception: pass
    else:
        image = await asyncio.to_thread(grab, display, width, height)
    dimensions = {"width": image.width, "height": image.height}
    return await asyncio.to_thread(png, image), dimensions
