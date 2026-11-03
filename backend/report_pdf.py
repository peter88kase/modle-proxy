"""PDF 测试报告生成（ReportLab）。

报告只呈现本次测试的真实数据：测试项来自运行绑定的标准版本快照，结果来自实际
执行记录与人工确认，判定由后端 ``standards.conclusion`` 计算后写入。生成时不读
取任何凭证字段，且对动态文本再做一次脱敏与长度截断。
"""

from __future__ import annotations

import io
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .config import BASE_DIR
from .security import redact_text
from .standards import FAIL as STATUS_FAIL
from .standards import STATUS_LABELS, VERDICT_FAIL, VERDICT_PARTIAL, VERDICT_PASS

FONT_NAME = "ReportCJK"
FONT_BOLD = "ReportCJK-Bold"
BUNDLED_FONT = BASE_DIR / "assets" / "fonts" / "NotoSansSC-Regular-subset.ttf"
SYSTEM_FONT_CANDIDATES = (
    "/usr/share/fonts/google-noto-sans-cjk-ttc-fonts/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/wqy-zenhei/wqy-zenhei.ttc",
    "C:/Windows/Fonts/msyh.ttc",
)

_registered = False
_font_source = ""


def _register_fonts() -> str:
    """Register a CJK-capable font once; returns a human readable source label."""
    global _registered, _font_source
    if _registered:
        return _font_source

    candidates: list[Path] = []
    env_font = os.environ.get("REPORT_FONT_PATH", "").strip()
    if env_font:
        candidates.append(Path(env_font))
    if BUNDLED_FONT.is_file():
        candidates.append(BUNDLED_FONT)
    candidates.extend(Path(p) for p in SYSTEM_FONT_CANDIDATES)

    for path in candidates:
        try:
            if not path.is_file():
                continue
            pdfmetrics.registerFont(TTFont(FONT_NAME, str(path)))
            pdfmetrics.registerFont(TTFont(FONT_BOLD, str(path)))
            _font_source = f"内嵌字体 {path.name}" if path == BUNDLED_FONT else f"系统字体 {path.name}"
            _registered = True
            return _font_source
        except Exception:  # noqa: BLE001 - 尝试下一个候选字体
            continue

    # 最后兜底：ReportLab 内置 CID 字体，不嵌入字形，依赖阅读器自带中文字体
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    globals()["FONT_NAME"] = "STSong-Light"
    globals()["FONT_BOLD"] = "STSong-Light"
    _font_source = "内置 CID 字体 STSong-Light（未嵌入）"
    _registered = True
    return _font_source


def font_source() -> str:
    _register_fonts()
    return _font_source


# ---------------------------------------------------------------------------
# 文本处理
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(authorization|x-api-key|cookie|set-cookie)\s*[:=]\s*\S+"),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),
]


def clean(text: Any, limit: int = 400) -> str:
    value = "" if text is None else str(text)
    value = redact_text(value, limit * 2)
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub("[已脱敏]", value)
    value = value.replace("\r", " ").replace("\n", " ").strip()
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return value


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class _NumberedCanvas:
    """Mix-in factory producing page numbers with the total page count."""

    @staticmethod
    def make(report_no: str, font: str):
        from reportlab.pdfgen import canvas as _canvas

        class NumberedCanvas(_canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):  # noqa: N802 - ReportLab API
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self._draw_footer(total)
                    super().showPage()
                super().save()

            def _draw_footer(self, total: int):
                """页脚只留报告标识。

                对外报告不需要“第 x 页 / 共 y 页”：页数会随标准项增减而变，
                对阅读方没有信息量，反而每页都在提示这是系统导出的临时文件。
                """
                self.setFont(font, 8)
                self.setFillColor(colors.HexColor("#555555"))
                self.drawString(18 * mm, 12 * mm, f"{report_no} · 模型接口测试平台")

        return NumberedCanvas


# ---------------------------------------------------------------------------
# 样式
# ---------------------------------------------------------------------------
def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle(
        "base",
        fontName=FONT_NAME,
        fontSize=9,
        leading=13,
        textColor=colors.black,
        alignment=TA_LEFT,
    )
    return {
        "title": ParagraphStyle("title", parent=base, fontSize=20, leading=26, spaceAfter=2),
        "subtitle": ParagraphStyle("subtitle", parent=base, fontSize=9, leading=13, textColor=colors.HexColor("#444444")),
        "h2": ParagraphStyle(
            "h2", parent=base, fontSize=11.5, leading=16, spaceBefore=10, spaceAfter=5, keepWithNext=True
        ),
        "h3": ParagraphStyle(
            "h3", parent=base, fontSize=9.5, leading=13, spaceBefore=4, spaceAfter=3, keepWithNext=True
        ),
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=11.5),
        "smallKeep": ParagraphStyle("smallKeep", parent=base, fontSize=8, leading=11.5, keepWithNext=True),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.2, leading=9.6),
        "cellhead": ParagraphStyle("cellhead", parent=base, fontSize=7.4, leading=10),
        "verdict": ParagraphStyle("verdict", parent=base, fontSize=15, leading=20),
    }


def _kv_table(rows: list[tuple[str, str]], styles: dict[str, ParagraphStyle], width: float) -> Table:
    data = [
        [Paragraph(_escape(k), styles["small"]), Paragraph(_escape(v), styles["small"])]
        for k, v in rows
    ]
    table = Table(data, colWidths=[width * 0.22, width * 0.78])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F2F2")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


SUITE_SECTION_TITLES = {
    "NET": "1.3 端点与网络连通性（NET）",
    "REQ": "1.4 普通请求（REQ）",
    "STREAM": "1.5 流式请求（STREAM）",
    "AUTH": "1.6 鉴权（AUTH）",
    "MODEL": "1.7 模型 ID 与权限边界（MODEL）",
    "TIME": "1.8 超时与失败返回（TIME）",
}

SUITE_RESULT_LABELS = {"PASS": "通过", "FAIL": "不通过", "SKIP": "未执行"}


def _grid(rows: int, cols: int) -> list[tuple]:
    return [
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#AAAAAA")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]


SCOPE_NAMES = {
    1: "连通性与鉴权",
    2: "接口兼容性",
    3: "缓存正确性",
    4: "模型与能力真实性",
}

#: 对外口径：内部状态名不适合出现在交付物里（blocked / undefined 会被误读成系统故障）。
STATUS_OUT = {
    "pass": "通过",
    "fail": "未通过",
    "not_tested": "未执行",
    "blocked": "未执行",
    "pending": "待确认",
    "undefined": "未判定",
    "not_applicable": "不适用",
}


def _scope_name(chapter: int) -> str:
    return SCOPE_NAMES.get(int(chapter), f"第 {chapter} 部分")


def _scope_table(entries: list[dict[str, Any]], styles, width: float) -> Table:
    """按测试范围汇总：一眼看出问题集中在哪一块。"""
    header = ["测试范围", "检查项", "通过", "未通过", "未执行", "待确认"]
    ratios = [0.32, 0.14, 0.13, 0.13, 0.14, 0.14]
    buckets: dict[int, dict[str, int]] = {}
    for entry in entries:
        bucket = buckets.setdefault(int(entry["chapter"]), {"total": 0, "pass": 0, "fail": 0, "run": 0, "pending": 0})
        bucket["total"] += 1
        status = entry["status"]
        if status == "pass":
            bucket["pass"] += 1
        elif status == "fail":
            bucket["fail"] += 1
        elif status == "pending":
            bucket["pending"] += 1
        elif status in {"blocked", "not_tested"}:
            bucket["run"] += 1

    data = [[Paragraph(h, styles["cellhead"]) for h in header]]
    for chapter in sorted(buckets):
        bucket = buckets[chapter]
        data.append(
            [
                Paragraph(_escape(_scope_name(chapter)), styles["cell"]),
                Paragraph(str(bucket["total"]), styles["cell"]),
                Paragraph(str(bucket["pass"]), styles["cell"]),
                Paragraph(str(bucket["fail"]), styles["cell"]),
                Paragraph(str(bucket["run"]), styles["cell"]),
                Paragraph(str(bucket["pending"]), styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[width * r for r in ratios], repeatRows=1)
    table.setStyle(TableStyle(_grid(len(data), len(header))))
    return table


def _external_note(entry: dict[str, Any]) -> str:
    """对外说明列：只写读者需要知道的一句话，不搬内部报错与状态名。"""
    status = entry["status"]
    if status == "fail":
        return clean(entry.get("actual") or entry.get("reason") or "", 120)
    if status == "pending":
        return "需人工确认"
    if status == "undefined":
        return "本次未判定"
    if status in {"blocked", "not_tested"}:
        return ""
    return ""


def _legacy_case_table(cases: list[dict[str, Any]], styles, width: float) -> Table:
    """旧标准不含第一章时，把当时的原始执行记录附在报告末尾备查。"""
    header = ["编号", "用例", "结果"]
    data = [[Paragraph(h, styles["cellhead"]) for h in header]]
    for row in cases:
        data.append(
            [
                Paragraph(_escape(str(row["case_id"])), styles["cell"]),
                Paragraph(_escape(clean(row.get("title"), 60)), styles["cell"]),
                Paragraph(_escape(SUITE_RESULT_LABELS.get(str(row["result"]), str(row["result"]))), styles["cell"]),
            ]
        )
    table = Table(data, colWidths=[width * 0.14, width * 0.64, width * 0.22], repeatRows=1)
    table.setStyle(TableStyle(_grid(len(data), len(header))))
    return table


def _detail_table(
    entries: list[dict[str, Any]], styles: dict[str, ParagraphStyle], width: float
) -> Table:
    """逐项结果：编号 / 检查项 / 结果 / 说明，按测试范围分组。"""
    header = ["编号", "检查项", "结果", "说明"]
    ratios = [0.12, 0.34, 0.10, 0.44]
    chapter_totals: dict[int, int] = {}
    for entry in entries:
        chapter_totals[int(entry["chapter"])] = chapter_totals.get(int(entry["chapter"]), 0) + 1

    data = [[Paragraph(h, styles["cellhead"]) for h in header]]
    group_rows: list[int] = []
    fail_rows: list[int] = []
    current: int | None = None
    for entry in entries:
        chapter = int(entry["chapter"])
        if chapter != current:
            current = chapter
            label = f"{_scope_name(chapter)}（{chapter_totals[chapter]} 项）"
            data.append([Paragraph(f"<b>{_escape(label)}</b>", styles["cell"])] + [""] * (len(header) - 1))
            group_rows.append(len(data) - 1)
        status = entry["status"]
        data.append(
            [
                Paragraph(_escape(entry.get("display_id") or entry["item_id"]), styles["cell"]),
                Paragraph(_escape(clean(entry["name"], 60)), styles["cell"]),
                Paragraph(_escape(STATUS_OUT.get(status, status)), styles["cell"]),
                Paragraph(_escape(_external_note(entry)), styles["cell"]),
            ]
        )
        if status == "fail":
            fail_rows.append(len(data) - 1)

    table = Table(data, colWidths=[width * r for r in ratios], repeatRows=1)
    style = _grid(len(data), len(header))
    for row_index in group_rows:
        style.append(("SPAN", (0, row_index), (-1, row_index)))
        style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#F2F2F2")))
    for row_index in fail_rows:
        style.append(("BACKGROUND", (0, row_index), (-1, row_index), colors.HexColor("#FBE9E9")))
    table.setStyle(TableStyle(style))
    return table


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
MARGIN = 18 * mm


def _render(story: list[Any], report_no: str, title: str, subject: str) -> bytes:
    """把 story 渲染成 PDF 字节。单任务报告与多模型报告共用同一套页面模板。"""
    _register_fonts()
    buffer = io.BytesIO()
    width = A4[0] - 2 * MARGIN
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=f"{title} {report_no}",
        author="模型接口测试平台",
        subject=subject,
    )
    frame = Frame(MARGIN, 18 * mm, width, A4[1] - 16 * mm - 18 * mm, id="body")
    doc.addPageTemplates([PageTemplate(id="report", frames=[frame])])
    doc.build(story, canvasmaker=_NumberedCanvas.make(report_no, FONT_NAME))
    return buffer.getvalue()


def _task_story(context: dict[str, Any], styles: dict[str, ParagraphStyle], width: float) -> list[Any]:
    """单个模型的对外报告正文。

    对外交付只看四件事：测了什么、结论是什么、哪些项没过、每一项的判定明细。
    Word 文档名、标准校验值、任务/批次编号、执行进度、页数这类内部运行信息一律不出现。
    """
    report_no = context["report_no"]
    verdict = context["conclusion"]
    verdict_text = verdict["verdict"]
    counts = verdict["counts"]
    entries = context["entries"]
    generated = str(context.get("generated_at") or "")[:10]
    not_run = sum(1 for e in entries if e["status"] in {"blocked", "not_tested"})
    pending = int(counts.get("pending", 0))
    failed = [entry for entry in entries if entry["status"] == "fail"]

    story: list[Any] = []
    story.append(Paragraph("模型接口接入测试报告", styles["title"]))
    story.append(
        Paragraph(
            f"报告编号：{_escape(report_no)}　　出具日期：{_escape(generated)}",
            styles["subtitle"],
        )
    )
    story.append(Spacer(1, 10))

    summary = (
        f"共 {len(entries)} 项检查：通过 {counts.get('pass', 0)} 项、"
        f"未通过 {counts.get('fail', 0)} 项、未执行 {not_run} 项"
    )
    if pending:
        summary += f"、待确认 {pending} 项"
    verdict_table = Table(
        [
            [
                Paragraph("<b>整体结论</b>", styles["small"]),
                Paragraph(f"<b>{_escape(verdict_text)}</b>", styles["verdict"]),
                Paragraph(_escape(summary), styles["small"]),
            ]
        ],
        colWidths=[width * 0.16, width * 0.20, width * 0.64],
    )
    verdict_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#666666")),
                ("BACKGROUND", (0, 0), (-1, -1), _verdict_color(verdict_text)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("一、被测对象", styles["h2"]))
    story.append(_kv_table(context["meta_rows"], styles, width))
    story.append(Spacer(1, 6))

    story.append(Paragraph("二、结果统计", styles["h2"]))
    stat_rows = [
        ("检查项", str(len(entries))),
        ("通过", str(counts.get("pass", 0))),
        ("未通过", str(counts.get("fail", 0))),
        ("未执行", str(not_run)),
        ("待确认", str(pending)),
        ("不适用 / 未启用", str(verdict["excluded"])),
    ]
    stat_data = [
        [Paragraph(_escape(label), styles["cellhead"]), Paragraph(_escape(value), styles["cell"])]
        for label, value in stat_rows
    ]
    # 三组并排，避免一张六行两列的表占掉半页
    merged: list[list[Any]] = []
    for index in range(0, len(stat_data), 3):
        row = stat_data[index:index + 3]
        while len(row) < 3:
            row.append([Paragraph("", styles["cell"]), Paragraph("", styles["cell"])])
        merged.append(row[0] + row[1] + row[2])
    stat_table = Table(merged, colWidths=[width * 0.17, width * 0.12] * 3, hAlign="LEFT")
    stat_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BBBBBB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F2F2")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F2F2F2")),
                ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#F2F2F2")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    story.append(stat_table)
    story.append(Spacer(1, 6))
    story.append(Paragraph("按测试范围", styles["h3"]))
    story.append(_scope_table(entries, styles, width))
    story.append(Spacer(1, 8))

    story.append(Paragraph("三、主要问题", styles["h2"]))
    if failed:
        story.append(
            Paragraph(
                f"{len(failed)} 项未通过。以下项目在整改并复测通过前，不能视为满足接入要求。",
                styles["small"],
            )
        )
        story.append(Spacer(1, 4))
        rows = [[Paragraph(h, styles["cellhead"]) for h in ("编号", "检查项", "实际结果")]]
        for entry in failed:
            rows.append(
                [
                    Paragraph(_escape(str(entry.get("display_id") or entry["item_id"])), styles["cell"]),
                    Paragraph(_escape(clean(entry["name"], 40)), styles["cell"]),
                    Paragraph(_escape(clean(entry.get("actual") or entry.get("reason") or "", 160)), styles["cell"]),
                ]
            )
        table = Table(rows, colWidths=[width * 0.14, width * 0.3, width * 0.56], repeatRows=1)
        table.setStyle(TableStyle(_grid(len(rows), 3)))
        story.append(table)
        story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("本次测试没有未通过项。", styles["small"]))
        story.append(Spacer(1, 4))

    if not_run:
        reason = str(context.get("incomplete_reason") or "").strip()
        detail = f"（{reason}）" if reason else ""
        story.append(
            Paragraph(
                f"另有 {not_run} 项本次未执行{detail}，因此不计入通过。"
                "未执行项目需要在具备条件后补测，才能作为完整结论的依据。",
                styles["small"],
            )
        )
        story.append(Spacer(1, 6))

    story.append(Paragraph("四、结论说明", styles["h2"]))
    story.append(KeepTogether([Paragraph(_escape(line), styles["small"]) for line in context["notes"]]))
    story.append(Spacer(1, 8))

    story.append(PageBreak())
    story.append(Paragraph("五、逐项结果", styles["h2"]))
    story.append(
        Paragraph(
            "下表按测试范围列出全部检查项的结果。编号与测试标准一一对应，便于对照与复测。",
            styles["smallKeep"],
        )
    )
    story.append(Spacer(1, 4))
    story.append(_detail_table(entries, styles, width))

    evidence = context.get("evidence") or []
    if evidence:
        story.append(Spacer(1, 10))
        story.append(Paragraph("六、附件：人工确认证据", styles["h2"]))
        story.append(
            Paragraph(
                "以下材料由测试人员上传，用于支撑人工确认项；平台只登记文件名与时间。",
                styles["small"],
            )
        )
        story.append(Spacer(1, 4))
        ev_rows = [[Paragraph(h, styles["cellhead"]) for h in ("编号", "文件", "说明", "上传时间")]]
        for row in evidence:
            ev_rows.append(
                [
                    Paragraph(_escape(str(row.get("item_id") or "")), styles["cell"]),
                    Paragraph(_escape(clean(str(row.get("filename") or ""), 50)), styles["cell"]),
                    Paragraph(_escape(clean(str(row.get("note") or "—"), 60)), styles["cell"]),
                    Paragraph(_escape(_short_time(row.get("created_at"))), styles["cell"]),
                ]
            )
        ev_table = Table(ev_rows, colWidths=[width * 0.14, width * 0.36, width * 0.3, width * 0.2], repeatRows=1)
        ev_table.setStyle(TableStyle(_grid(len(ev_rows), 4)))
        story.append(ev_table)

    # 旧版本标准不含第一章时，原始执行记录仍要留档（只作附录，不参与结论）。
    legacy_cases = context.get("suite_cases") or []
    if legacy_cases and not context.get("has_first_chapter", True):
        story.append(Spacer(1, 8))
        story.append(Paragraph("附录：历史执行记录（仅供参考，不参与本次结论）", styles["h3"]))
        story.append(_legacy_case_table(legacy_cases, styles, width))
    return story


def build_report(context: dict[str, Any]) -> bytes:
    """渲染单任务报告。``context`` 由 ``standards_api.build_context()`` 产生。"""
    _register_fonts()
    styles = _styles()
    story = _task_story(context, styles, A4[0] - 2 * MARGIN)
    return _render(story, context["report_no"], "测试结果报告", "模型接口测试结果报告")


def suggested_filename(report_no: str, created_at: str) -> str:
    stamp = re.sub(r"\D", "", (created_at or "")[:10]) or datetime.now().strftime("%Y%m%d")
    suffix = report_no.rsplit("-", 1)[-1]
    return f"测试结果报告_{stamp}_{suffix}.pdf"


# ---------------------------------------------------------------------------
# 多模型合并报告
# ---------------------------------------------------------------------------
def _short_time(value: Any) -> str:
    """ISO 时间 → 「2026-10-30 10:13（UTC）」，对外不暴露 T/+00:00 这种机器写法。"""
    text = str(value or "").strip()
    if not text:
        return "—"
    return text.replace("T", " ")[:16] + "（UTC）"


def _verdict_color(text: str):
    return {
        VERDICT_PASS: colors.HexColor("#E6F4EA"),
        VERDICT_FAIL: colors.HexColor("#FBE9E9"),
        VERDICT_PARTIAL: colors.HexColor("#FFF4E5"),
    }.get(text, colors.HexColor("#FFF4E5"))


def _grid_table(data: list[list[Any]], widths: list[float]) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#AAAAAA")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    return table


def _batch_summary_table(contexts: list[dict[str, Any]], styles, width: float) -> Table:
    """一行一个模型：结论 + 计数 + 失败项编号。评审方先看这张表。"""
    head = ["模型", "结论", "检查项", "通过", "未通过", "未执行", "待确认", "未通过项"]
    rows: list[list[Any]] = [[Paragraph(f"<b>{_escape(h)}</b>", styles["cellhead"]) for h in head]]
    for ctx in contexts:
        verdict = ctx["conclusion"]
        counts = verdict["counts"]
        failed = [e for e in ctx["entries"] if e["status"] == STATUS_FAIL]
        failed_ids = "、".join(str(e["display_id"]) for e in failed) or "—"
        rows.append(
            [
                Paragraph(_escape(str(ctx.get("model") or "")), styles["cell"]),
                Paragraph(_escape(verdict["verdict"]), styles["cell"]),
                Paragraph(str(verdict["applicable"]), styles["cell"]),
                Paragraph(str(counts.get("pass", 0)), styles["cell"]),
                Paragraph(str(counts.get("fail", 0)), styles["cell"]),
                Paragraph(str(counts.get("not_tested", 0) + counts.get("blocked", 0)), styles["cell"]),
                Paragraph(str(counts.get("pending", 0)), styles["cell"]),
                Paragraph(_escape(failed_ids), styles["cell"]),
            ]
        )
    widths = [
        width * 0.22, width * 0.12, width * 0.09, width * 0.08,
        width * 0.09, width * 0.09, width * 0.09, width * 0.22,
    ]
    table = _grid_table(rows, widths)
    # 结论列按结论着色：不达标一眼能看见
    for index, ctx in enumerate(contexts, start=1):
        table.setStyle(
            TableStyle([("BACKGROUND", (1, index), (1, index), _verdict_color(ctx["conclusion"]["verdict"]))])
        )
    return table


def build_batch_report(contexts: list[dict[str, Any]], batch: dict[str, Any]) -> bytes:
    """把一次提交里的多个模型合并成**一份** PDF。

    结构：
      封面结论（整批）→ 一、批次信息 → 二、模型汇总表 → 三、失败模型清单
      → 四、逐模型明细（每个模型一份完整报告，从新页开始）

    "哪些模型失败了"必须在第三节单独成表，而不是只躺在汇总表的颜色里：
    评审方要能直接抄走失败清单，不用自己数。
    """
    if not contexts:
        raise ValueError("批量报告至少需要一个模型的结果")
    _register_fonts()
    styles = _styles()
    width = A4[0] - 2 * MARGIN
    report_no = str(batch.get("report_no") or "")

    failed_contexts = [
        ctx for ctx in contexts
        if any(e["status"] == STATUS_FAIL for e in ctx["entries"])
    ]
    passed_names = [str(c.get("model") or "") for c in contexts if c not in failed_contexts]

    overall = VERDICT_FAIL if failed_contexts else (
        VERDICT_PARTIAL
        if any(c["conclusion"]["verdict"] == VERDICT_PARTIAL for c in contexts)
        else VERDICT_PASS
    )

    story: list[Any] = []
    story.append(Paragraph("模型接口接入测试报告（多模型）", styles["title"]))
    story.append(
        Paragraph(
            f"报告编号：{_escape(report_no)}　　"
            f"出具日期：{_escape(str(contexts[0]['generated_at'])[:10])}　　"
            f"被测模型：{len(contexts)} 个",
            styles["subtitle"],
        )
    )
    story.append(Spacer(1, 8))

    overall_table = Table(
        [
            [
                Paragraph("<b>整批结论</b>", styles["small"]),
                Paragraph(f"<b>{_escape(overall)}</b>", styles["verdict"]),
                Paragraph(
                    _escape(
                        f"{len(contexts)} 个模型中 {len(failed_contexts)} 个存在不通过项"
                        + ("" if failed_contexts else f"；全部通过：{'、'.join(passed_names)}")
                    ),
                    styles["small"],
                ),
            ]
        ],
        colWidths=[width * 0.16, width * 0.22, width * 0.62],
    )
    overall_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#666666")),
                ("BACKGROUND", (0, 0), (-1, -1), _verdict_color(overall)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(overall_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("一、被测对象", styles["h2"]))
    batch_rows = [
        ("被测模型", "、".join(str(c.get("model") or "") for c in contexts)),
        ("测试时间", _short_time(batch.get("created_at"))),
        ("测试依据", str(contexts[0].get("standard_label") or "")),
        ("说明", "每个模型独立执行一次完整检查；本报告按模型分别给出结论，不跨模型继承。"),
    ]
    story.append(_kv_table(batch_rows, styles, width))
    story.append(Spacer(1, 8))

    story.append(Paragraph("二、各模型结果", styles["h2"]))
    story.append(_batch_summary_table(contexts, styles, width))
    story.append(Spacer(1, 10))

    story.append(Paragraph("三、未通过项清单", styles["h2"]))
    if not failed_contexts:
        story.append(Paragraph("本次测试没有任何模型出现未通过项。", styles["small"]))
    else:
        story.append(
            Paragraph(
                f"共 {len(failed_contexts)} 个模型存在未通过项："
                + "、".join(str(c.get("model") or "") for c in failed_contexts),
                styles["small"],
            )
        )
        story.append(Spacer(1, 4))
        fail_rows: list[list[Any]] = [
            [Paragraph(f"<b>{_escape(h)}</b>", styles["cellhead"])
             for h in ("模型", "编号", "检查项", "实际结果")]
        ]
        for ctx in failed_contexts:
            first = True
            for entry in ctx["entries"]:
                if entry["status"] != STATUS_FAIL:
                    continue
                fail_rows.append(
                    [
                        Paragraph(_escape(str(ctx.get("model") or "") if first else ""), styles["cell"]),
                        Paragraph(_escape(str(entry["display_id"])), styles["cell"]),
                        Paragraph(_escape(str(entry["name"])), styles["cell"]),
                        Paragraph(_escape(clean(entry.get("actual") or entry.get("note") or "")), styles["cell"]),
                    ]
                )
                first = False
        story.append(
            _grid_table(fail_rows, [width * 0.2, width * 0.1, width * 0.22, width * 0.48])
        )
    story.append(Spacer(1, 6))

    story.append(Paragraph("四、逐模型明细", styles["h2"]))
    story.append(
        Paragraph("以下每个模型各附一份完整报告，结构与本报告一致。", styles["small"])
    )

    for ctx in contexts:
        story.append(PageBreak())
        story.extend(_task_story(ctx, styles, width))

    return _render(story, report_no or "BATCH", "多模型测试结果报告", "多模型接口测试合并报告")
