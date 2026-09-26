"""Browser smoke test for the case produced by make_report_demo (synthetic data)."""
import argparse
from pathlib import Path
import re
import tempfile
from playwright.sync_api import sync_playwright, expect
from scripts.check_media_browser import check_media, check_media_hierarchy, check_on_demand, check_video_conversion
from scripts.check_file_browser import check_explorer, make_stress_case, check_stress_explorer


def check(root):
    errors=[];network=[];allowed=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        context=browser.new_context(viewport={"width":1440,"height":1100})
        context.route(re.compile(r"https?://"),lambda route:route.continue_() if any(route.request.url.startswith(url) for url in allowed) else (network.append(route.request.url),route.abort()))
        page=context.new_page();page.on("pageerror",lambda error:errors.append(str(error)))
        page.on("dialog",lambda dialog:(errors.append("Unexpected dialog"),dialog.dismiss()))
        def visit(name):page.goto((root/name).as_uri())
        visit("report.html")
        expect(page.locator("h1")).to_have_text("Recovery overview")
        page.screenshot(path=str(root/"overview.png"),full_page=True)
        visit("crypto.html")
        expect(page.locator("#results article")).to_have_count(1)
        expect(page.locator("#results")).to_contain_text("encrypted")
        visit("evidence.html")
        expect(page.locator("#results article")).to_have_count(48)
        page.get_by_role("button",name="Next page").click()
        expect(page.locator("#pagination")).to_contain_text("Page 2")
        check_explorer(page, root)
        check_media(page, root)
        with tempfile.TemporaryDirectory(prefix="cold-digger-media-folders-") as tmp:
            check_media_hierarchy(page, Path(tmp))
        with tempfile.TemporaryDirectory(prefix="cold-digger-explorer-test-") as tmp:
            stress = Path(tmp); ids = make_stress_case(stress)
            check_stress_explorer(page, stress, ids)
        with tempfile.TemporaryDirectory(prefix="cold-digger-browser-read-") as tmp:
            check_on_demand(page, Path(tmp), allowed)
        with tempfile.TemporaryDirectory(prefix="cold-digger-video-playback-") as tmp:
            check_video_conversion(page, Path(tmp), allowed)
        assert not errors,errors
        assert not network,network
        browser.close()
    print("PASS: overview, evidence pagination, file explorer navigation, sorting, search, filters, details, previews, deep links, responsive layout, gallery paging, keyboard navigation, video playback, escaped filenames, 52,000-file search, bounded folder tree/cache, failure retry, and no outbound requests")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("demo",type=Path)
    check(parser.parse_args().demo.resolve())
