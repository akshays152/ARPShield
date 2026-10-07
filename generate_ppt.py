"""
ARPShield — Premium Cybersecurity Capstone Presentation Generator
Generates a visually stunning 18-slide PPTX with dark SOC-style theme.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

# ══════════════════════════════════════════════════════════════
# COLOR PALETTE — Dark Cybersecurity Theme
# ══════════════════════════════════════════════════════════════
BG_DARK       = RGBColor(0x0B, 0x0E, 0x17)   # Near-black navy
BG_CARD       = RGBColor(0x12, 0x17, 0x24)   # Slightly lighter card bg
BG_CARD_ALT   = RGBColor(0x16, 0x1C, 0x2E)   # Alternative card bg
ACCENT_BLUE   = RGBColor(0x00, 0x7B, 0xFF)   # Electric blue
ACCENT_CYAN   = RGBColor(0x00, 0xD4, 0xFF)   # Cyan
ACCENT_RED    = RGBColor(0xFF, 0x3B, 0x3B)   # Alert red
ACCENT_GREEN  = RGBColor(0x00, 0xE6, 0x76)   # Success green
ACCENT_AMBER  = RGBColor(0xFF, 0xB8, 0x00)   # Warning amber
TEXT_WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
TEXT_LIGHT     = RGBColor(0xC8, 0xD0, 0xE0)   # Light gray
TEXT_DIM       = RGBColor(0x6B, 0x74, 0x8C)   # Dim text
DIVIDER_COLOR  = RGBColor(0x1E, 0x27, 0x3B)   # Subtle divider

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

# ══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def set_slide_bg(slide, color=BG_DARK):
    """Set solid background color for a slide."""
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_shape(slide, left, top, width, height, fill_color=None, line_color=None, shape=MSO_SHAPE.RECTANGLE):
    """Add a shape to the slide."""
    s = slide.shapes.add_shape(shape, left, top, width, height)
    s.shadow.inherit = False
    if fill_color:
        s.fill.solid()
        s.fill.fore_color.rgb = fill_color
    else:
        s.fill.background()
    if line_color:
        s.line.color.rgb = line_color
        s.line.width = Pt(1)
    else:
        s.line.fill.background()
    return s

def add_rounded_rect(slide, left, top, width, height, fill_color=BG_CARD, line_color=None):
    """Add a rounded rectangle card."""
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    s.shadow.inherit = False
    s.fill.solid()
    s.fill.fore_color.rgb = fill_color
    if line_color:
        s.line.color.rgb = line_color
        s.line.width = Pt(1)
    else:
        s.line.fill.background()
    # Adjust corner rounding
    try:
        s._element.attrib['{http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing}editAs'] = 'oneCell'
    except:
        pass
    return s

def add_text(slide, text, left, top, width, height, font_size=14, color=TEXT_WHITE,
             bold=False, alignment=PP_ALIGN.LEFT, font_name="Calibri", anchor=MSO_ANCHOR.TOP):
    """Add a text box to the slide."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    try:
        tf.vertical_anchor = anchor
    except:
        pass
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return txBox

def add_multiline_text(slide, lines, left, top, width, height, default_size=14,
                       default_color=TEXT_WHITE, font_name="Calibri", alignment=PP_ALIGN.LEFT,
                       anchor=MSO_ANCHOR.TOP, line_spacing=1.2):
    """Add multi-line text where each line is a tuple: (text, size, color, bold)."""
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    try:
        tf.vertical_anchor = anchor
    except:
        pass
    
    for i, line_data in enumerate(lines):
        if isinstance(line_data, str):
            text, size, color, bold = line_data, default_size, default_color, False
        elif len(line_data) == 2:
            text, size = line_data
            color, bold = default_color, False
        elif len(line_data) == 3:
            text, size, color = line_data
            bold = False
        else:
            text, size, color, bold = line_data
        
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        
        p.text = text
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.font.bold = bold
        p.font.name = font_name
        p.alignment = alignment
        p.space_after = Pt(2)
        try:
            p.line_spacing = line_spacing
        except:
            pass
    return txBox

def add_accent_line(slide, left, top, width, color=ACCENT_BLUE, thickness=3):
    """Add a horizontal accent line."""
    s = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, Pt(thickness))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s

def add_card(slide, left, top, width, height, title, body, accent_color=ACCENT_BLUE,
             title_size=13, body_size=11, body_color=TEXT_LIGHT):
    """Add a styled card with accent top border."""
    # Card background
    add_rounded_rect(slide, left, top, width, height, fill_color=BG_CARD)
    # Accent top bar
    add_shape(slide, left + Inches(0.05), top + Inches(0.05), width - Inches(0.1), Pt(3), fill_color=accent_color)
    # Title
    add_text(slide, title, left + Inches(0.15), top + Inches(0.18), width - Inches(0.3), Inches(0.35),
             font_size=title_size, color=accent_color, bold=True)
    # Body
    add_text(slide, body, left + Inches(0.15), top + Inches(0.5), width - Inches(0.3), height - Inches(0.6),
             font_size=body_size, color=body_color)

def add_kpi_card(slide, left, top, width, height, value, label, accent_color=ACCENT_CYAN):
    """Add a large KPI metric card."""
    add_rounded_rect(slide, left, top, width, height, fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    # Value
    add_text(slide, value, left, top + Inches(0.2), width, Inches(0.7),
             font_size=36, color=accent_color, bold=True, alignment=PP_ALIGN.CENTER)
    # Label
    add_text(slide, label, left, top + Inches(0.9), width, Inches(0.4),
             font_size=11, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)

def add_pipeline_step(slide, left, top, width, height, label, accent_color=ACCENT_BLUE):
    """Add a pipeline step box."""
    add_rounded_rect(slide, left, top, width, height, fill_color=BG_CARD, line_color=accent_color)
    add_text(slide, label, left, top, width, height,
             font_size=11, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)

def add_arrow_down(slide, cx, top, length, color=ACCENT_BLUE):
    """Add a downward arrow."""
    s = slide.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, cx - Inches(0.12), top, Inches(0.24), length)
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s

def add_arrow_right(slide, left, cy, length, color=ACCENT_BLUE):
    """Add a rightward arrow."""
    s = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, left, cy - Inches(0.1), length, Inches(0.2))
    s.fill.solid()
    s.fill.fore_color.rgb = color
    s.line.fill.background()
    s.shadow.inherit = False
    return s

# ══════════════════════════════════════════════════════════════
# SLIDE BUILDERS
# ══════════════════════════════════════════════════════════════

def slide_01_hero(prs):
    """SLIDE 1 — HERO / TITLE"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # Blank
    set_slide_bg(slide)
    
    # Subtle network-security visual on the right side
    # Glowing network topology / packet-flow effect
    # Background lines
    for i in range(7, 14):
        add_shape(slide, Inches(i), Inches(0), Pt(0.5), SLIDE_H, fill_color=RGBColor(0x12, 0x16, 0x22))
    for i in range(1, 7):
        add_shape(slide, Inches(6), Inches(i), SLIDE_W - Inches(6), Pt(0.5), fill_color=RGBColor(0x12, 0x16, 0x22))
    
    # Network nodes (CLIENT -- SWITCH -- GATEWAY, ATTACKER)
    nodes = [
        (8.0, 2.0, "CLIENT", ACCENT_CYAN),
        (10.0, 2.0, "SWITCH", ACCENT_CYAN),
        (12.0, 2.0, "GATEWAY", ACCENT_GREEN),
        (10.0, 5.0, "ATTACKER", ACCENT_RED),
    ]
    for x, y, label, color in nodes:
        add_shape(slide, Inches(x) - Inches(0.4), Inches(y) - Inches(0.4),
                  Inches(0.8), Inches(0.8), fill_color=None, line_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, label, Inches(x) - Inches(0.6), Inches(y) + Inches(0.5),
                 Inches(1.2), Inches(0.25), font_size=10, color=color, bold=True, alignment=PP_ALIGN.CENTER)
    
    # Normal lines
    add_shape(slide, Inches(8.4), Inches(1.97), Inches(1.2), Pt(3), fill_color=ACCENT_CYAN)
    add_shape(slide, Inches(10.4), Inches(1.97), Inches(1.2), Pt(3), fill_color=ACCENT_GREEN)
    
    # Suspicious line (Attacker -> Switch)
    add_shape(slide, Inches(9.97), Inches(2.4), Pt(3), Inches(2.2), fill_color=ACCENT_RED)
    
    # Packet representation
    add_shape(slide, Inches(10.0), Inches(3.2), Inches(0.4), Inches(0.4), fill_color=ACCENT_RED, shape=MSO_SHAPE.OVAL)
    add_text(slide, "FORGED ARP TRAFFIC", Inches(10.5), Inches(3.2), Inches(2.0), Inches(0.4),
             font_size=10, color=ACCENT_RED, bold=True)
    
    # Left Side: Information Hierarchy
    # 1. ARPShield
    add_text(slide, "🛡️", Inches(0.8), Inches(1.0), Inches(0.8), Inches(0.8), font_size=50)
    add_text(slide, "ARPShield", Inches(1.6), Inches(1.15), Inches(5.0), Inches(0.8),
             font_size=54, color=ACCENT_CYAN, bold=True)
    
    # Divider
    add_accent_line(slide, Inches(0.8), Inches(2.1), Inches(4.5), color=ACCENT_BLUE, thickness=4)
    
    # 2. REAL-TIME ARP SPOOFING...
    add_multiline_text(slide, [
        ("REAL-TIME ARP SPOOFING", 20, TEXT_WHITE, True),
        ("DETECTION & DDOS", 20, TEXT_WHITE, True),
        ("PREVENTION SYSTEM", 20, TEXT_WHITE, True),
    ], Inches(0.8), Inches(2.4), Inches(5.0), Inches(1.5))
    
    # 3. Official project topic
    add_text(slide, "Official Topic:\nARP Spoofing Attack Detection to Prevent DDoS Attack",
             Inches(0.8), Inches(3.6), Inches(5.0), Inches(0.6), font_size=11, color=TEXT_LIGHT)
    
    # 4. Group / University
    add_text(slide, "GROUP 52\nVIT BHOPAL UNIVERSITY", Inches(0.8), Inches(4.5), Inches(5.0), Inches(0.6),
             font_size=13, color=ACCENT_BLUE, bold=True)
    
    # 5. Supervisor
    add_text(slide, "Supervisor: Dr. Sreevani Maddukuri", Inches(0.8), Inches(5.3), Inches(5.0), Inches(0.4),
             font_size=14, color=ACCENT_CYAN)
    
    # 6. Team members
    team1 = "Chintanika M  •  Rishima Sharma  •  Anju Kumari"
    team2 = "Akshay Singh  •  Oveiya K"
    add_text(slide, team1, Inches(0.8), Inches(6.3), Inches(10.0), Inches(0.3),
             font_size=11, color=TEXT_DIM)
    add_text(slide, team2, Inches(0.8), Inches(6.6), Inches(10.0), Inches(0.3),
             font_size=11, color=TEXT_DIM)


def slide_02_problem(prs):
    """SLIDE 2 — THE SECURITY PROBLEM"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    # Title
    add_text(slide, "THE SECURITY PROBLEM", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # LEGITIMATE flow (left)
    add_text(slide, "LEGITIMATE TRAFFIC", Inches(0.6), Inches(1.2), Inches(5.5), Inches(0.4),
             font_size=14, color=ACCENT_GREEN, bold=True)
    
    legit_nodes = [("VICTIM", 0.8), ("SWITCH", 2.8), ("GATEWAY", 4.8)]
    for label, x in legit_nodes:
        add_rounded_rect(slide, Inches(x), Inches(1.8), Inches(1.5), Inches(0.5),
                         fill_color=BG_CARD, line_color=ACCENT_GREEN)
        add_text(slide, label, Inches(x), Inches(1.8), Inches(1.5), Inches(0.5),
                 font_size=11, color=ACCENT_GREEN, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
    add_arrow_right(slide, Inches(2.3), Inches(2.05), Inches(0.5), ACCENT_GREEN)
    add_arrow_right(slide, Inches(4.3), Inches(2.05), Inches(0.5), ACCENT_GREEN)
    
    # ATTACK flow (left, below)
    add_text(slide, "ARP SPOOFING ATTACK", Inches(0.6), Inches(2.7), Inches(5.5), Inches(0.4),
             font_size=14, color=ACCENT_RED, bold=True)
    
    add_rounded_rect(slide, Inches(0.8), Inches(3.3), Inches(1.5), Inches(0.5),
                     fill_color=BG_CARD, line_color=ACCENT_RED)
    add_text(slide, "ATTACKER", Inches(0.8), Inches(3.3), Inches(1.5), Inches(0.5),
             font_size=11, color=ACCENT_RED, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
    
    add_arrow_down(slide, Inches(1.55), Inches(3.85), Inches(0.4), ACCENT_RED)
    
    add_rounded_rect(slide, Inches(0.8), Inches(4.35), Inches(1.5), Inches(0.45),
                     fill_color=BG_CARD, line_color=ACCENT_RED)
    add_text(slide, "FORGED ARP REPLY", Inches(0.8), Inches(4.35), Inches(1.5), Inches(0.45),
             font_size=9, color=ACCENT_RED, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
    
    add_arrow_down(slide, Inches(1.55), Inches(4.85), Inches(0.4), ACCENT_RED)
    
    add_rounded_rect(slide, Inches(0.4), Inches(5.35), Inches(2.3), Inches(0.55),
                     fill_color=RGBColor(0x2A, 0x10, 0x10), line_color=ACCENT_RED)
    add_text(slide, "VICTIM'S IP-MAC\nMAPPING CORRUPTED", Inches(0.4), Inches(5.35), Inches(2.3), Inches(0.55),
             font_size=9, color=ACCENT_RED, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
    
    # Three problem cards (right side)
    problems = [
        ("01", "ARP LACKS AUTHENTICATION", "The ARP protocol has no built-in verification mechanism for sender identity.", ACCENT_RED),
        ("02", "FORGED MAPPINGS ENABLE IMPERSONATION", "Attackers can associate their MAC with another host's IP, enabling MitM attacks.", ACCENT_AMBER),
        ("03", "NETWORK DISRUPTION → DoS CONDITIONS", "Corrupted ARP caches can cause traffic blackholes and denial of service.", ACCENT_RED),
    ]
    
    for i, (num, title, desc, color) in enumerate(problems):
        y = Inches(1.2) + Inches(i * 1.95)
        add_rounded_rect(slide, Inches(7.0), y, Inches(5.8), Inches(1.6), fill_color=BG_CARD, line_color=DIVIDER_COLOR)
        # Number badge
        add_rounded_rect(slide, Inches(7.2), y + Inches(0.15), Inches(0.55), Inches(0.55),
                         fill_color=color)
        add_text(slide, num, Inches(7.2), y + Inches(0.15), Inches(0.55), Inches(0.55),
                 font_size=20, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Title
        add_text(slide, title, Inches(7.95), y + Inches(0.15), Inches(4.6), Inches(0.4),
                 font_size=13, color=TEXT_WHITE, bold=True)
        # Description
        add_text(slide, desc, Inches(7.95), y + Inches(0.6), Inches(4.6), Inches(0.8),
                 font_size=10, color=TEXT_LIGHT)


def slide_03_what_arpshield_does(prs):
    """SLIDE 3 — WHAT ARPSHIELD DOES (Security Pipeline)"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "WHAT ARPShield DOES", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Horizontal pipeline
    stages = [
        ("MONITOR", "Capture live ARP\npackets via Scapy", ACCENT_CYAN),
        ("DETECT", "Apply 7 rule-based\nheuristic checks", ACCENT_BLUE),
        ("IDENTIFY", "Pinpoint attacker\nMAC & IP address", ACCENT_BLUE),
        ("ANALYZE", "Quantify DDoS\nimpact & disruption", ACCENT_AMBER),
        ("MITIGATE", "Isolate malicious\ndevice via firewall", ACCENT_RED),
        ("RECOVER", "Restore legitimate\nIP-MAC mappings", ACCENT_GREEN),
    ]
    
    start_x = 0.4
    box_w = 1.75
    gap = 0.2
    y_top = 2.2
    
    for i, (label, desc, color) in enumerate(stages):
        x = Inches(start_x + i * (box_w + gap))
        
        # Card
        add_rounded_rect(slide, x, Inches(y_top), Inches(box_w), Inches(2.8),
                         fill_color=BG_CARD, line_color=color)
        # Stage number circle
        add_shape(slide, x + Inches(0.55), Inches(y_top + 0.2), Inches(0.65), Inches(0.65),
                  fill_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, str(i + 1), x + Inches(0.55), Inches(y_top + 0.2), Inches(0.65), Inches(0.65),
                 font_size=22, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Label
        add_text(slide, label, x, Inches(y_top + 1.0), Inches(box_w), Inches(0.35),
                 font_size=15, color=color, bold=True, alignment=PP_ALIGN.CENTER)
        # Description
        add_text(slide, desc, x + Inches(0.1), Inches(y_top + 1.4), Inches(box_w - 0.2), Inches(0.9),
                 font_size=10, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
        
        # Arrow between stages
        if i < len(stages) - 1:
            arrow_x = x + Inches(box_w)
            add_arrow_right(slide, arrow_x, Inches(y_top + 1.4), Inches(gap), ACCENT_BLUE)
    
    # Bottom tagline
    add_text(slide, "From suspicious ARP traffic to actionable network defense.",
             Inches(0.5), Inches(6.0), Inches(12.3), Inches(0.4),
             font_size=14, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)


def slide_04_architecture(prs):
    """SLIDE 4 — SYSTEM ARCHITECTURE"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "SYSTEM ARCHITECTURE", Inches(0.6), Inches(0.15), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.7), Inches(2.5))
    
    # Main pipeline (vertical, left-center)
    pipeline_x = 1.0
    pipeline_w = 3.0
    step_h = 0.52
    gap_h = 0.12
    start_y = 1.1
    
    steps = [
        ("NETWORK  ·  ARP TRAFFIC", ACCENT_CYAN, "network/"),
        ("PACKET CAPTURE  (Scapy)", ACCENT_CYAN, "network/sniffer.py"),
        ("PACKET PARSING", ACCENT_BLUE, "network/parser.py"),
        ("IP-MAC BASELINE CHECK", ACCENT_BLUE, "config/trusted_baseline.json"),
        ("DETECTION ENGINE  (7 Rules)", ACCENT_BLUE, "detection/"),
        ("ATTACKER IDENTIFICATION", ACCENT_AMBER, "detection_engine/"),
        ("ALERT / LOGGING", ACCENT_AMBER, "backend/routes/alerts.py"),
        ("DDoS IMPACT ANALYSIS", ACCENT_AMBER, "testing/evaluation/"),
        ("MITIGATION  (ISOLATE)", ACCENT_RED, "prevention/"),
        ("DATABASE  (SQLite)", ACCENT_GREEN, "database/"),
        ("DASHBOARD  (Flask)", ACCENT_GREEN, "dashboard/"),
    ]
    
    for i, (label, color, module) in enumerate(steps):
        y = start_y + i * (step_h + gap_h)
        add_rounded_rect(slide, Inches(pipeline_x), Inches(y), Inches(pipeline_w), Inches(step_h),
                         fill_color=BG_CARD, line_color=color)
        add_text(slide, label, Inches(pipeline_x + 0.1), Inches(y), Inches(pipeline_w - 0.2), Inches(step_h),
                 font_size=10, color=color, bold=True, alignment=PP_ALIGN.LEFT,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Module path (right-aligned)
        add_text(slide, module, Inches(pipeline_x), Inches(y), Inches(pipeline_w - 0.1), Inches(step_h),
                 font_size=7, color=TEXT_DIM, alignment=PP_ALIGN.RIGHT,
                 anchor=MSO_ANCHOR.MIDDLE)
        
        # Arrow
        if i < len(steps) - 1:
            cx = pipeline_x + pipeline_w / 2
            add_arrow_down(slide, Inches(cx), Inches(y + step_h), Inches(gap_h), color)
    
    # Right side — Detection rules detail
    rules_x = 5.5
    add_text(slide, "DETECTION RULES", Inches(rules_x), Inches(1.1), Inches(4), Inches(0.4),
             font_size=16, color=ACCENT_BLUE, bold=True)
    add_accent_line(slide, Inches(rules_x), Inches(1.5), Inches(1.5), ACCENT_BLUE)
    
    rules = [
        ("BASELINE VIOLATION", "IP-MAC vs trusted config"),
        ("GATEWAY SPOOFING", "Non-gateway MAC claims gateway IP"),
        ("IP-MAC CONFLICT", "Known IP → new MAC address"),
        ("DUPLICATE IP", "Multiple MACs claim same IP"),
        ("MAC CHANGE", "Existing IP → changed MAC"),
        ("SUSPICIOUS REPLY", "Unsolicited gratuitous ARP"),
        ("RATE THRESHOLD", "Abnormal ARP packets-per-second"),
    ]
    
    for i, (rule, desc) in enumerate(rules):
        ry = 1.8 + i * 0.62
        add_rounded_rect(slide, Inches(rules_x), Inches(ry), Inches(3.8), Inches(0.52),
                         fill_color=BG_CARD, line_color=DIVIDER_COLOR)
        # Warning indicator
        add_shape(slide, Inches(rules_x + 0.08), Inches(ry + 0.12), Inches(0.06), Inches(0.28),
                  fill_color=ACCENT_RED)
        add_text(slide, rule, Inches(rules_x + 0.25), Inches(ry + 0.02), Inches(3.4), Inches(0.25),
                 font_size=10, color=TEXT_WHITE, bold=True)
        add_text(slide, desc, Inches(rules_x + 0.25), Inches(ry + 0.27), Inches(3.4), Inches(0.22),
                 font_size=8, color=TEXT_DIM)
    
    # No ML extension shown on live architecture slide


def slide_05_detection_engine(prs):
    """SLIDE 5 — DETECTION ENGINE"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "HOW ARPShield DETECTS SPOOFING", Inches(0.6), Inches(0.3), Inches(10), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(3.0))
    add_text(slide, "7 rule-based heuristic checks applied to every ARP packet in real-time",
             Inches(0.6), Inches(1.0), Inches(10), Inches(0.3),
             font_size=12, color=TEXT_DIM)
    
    # Detection cards in 2 rows
    cards = [
        ("BASELINE\nVIOLATION", "Known IP → unexpected MAC\nvs trusted_baseline.json", ACCENT_RED),
        ("GATEWAY\nSPOOFING", "Non-gateway MAC claims\ngateway IP in ARP reply", ACCENT_RED),
        ("IP-MAC\nCONFLICT", "Previously seen IP now\nassociated with new MAC", ACCENT_AMBER),
        ("DUPLICATE\nIP CLAIM", "Multiple distinct MACs\nclaim the same IP address", ACCENT_AMBER),
        ("MAC\nCHANGE", "Established IP-MAC pair\nchanges unexpectedly", ACCENT_AMBER),
        ("SUSPICIOUS\nARP REPLY", "Unsolicited gratuitous ARP\nwithout preceding request", ACCENT_BLUE),
        ("HIGH ARP\nRATE", "Abnormal packets-per-second\nDDoS/flood precursor", ACCENT_RED),
    ]
    
    card_w = 1.65
    card_h = 1.65
    gap = 0.15
    
    # Row 1: 4 cards
    for i in range(4):
        x = 0.5 + i * (card_w + gap)
        y = 1.6
        c = cards[i]
        add_rounded_rect(slide, Inches(x), Inches(y), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=c[2])
        # Warning triangle
        add_text(slide, "⚠", Inches(x + 0.05), Inches(y + 0.08), Inches(0.3), Inches(0.3),
                 font_size=16, color=c[2])
        add_text(slide, c[0], Inches(x + 0.1), Inches(y + 0.35), Inches(card_w - 0.2), Inches(0.55),
                 font_size=12, color=TEXT_WHITE, bold=True)
        add_text(slide, c[1], Inches(x + 0.1), Inches(y + 0.9), Inches(card_w - 0.2), Inches(0.65),
                 font_size=9, color=TEXT_LIGHT)
    
    # Row 2: 3 cards (centered)
    offset = 0.5 + (4 * (card_w + gap) - 3 * (card_w + gap) + gap) / 2
    for i in range(3):
        x = offset + i * (card_w + gap)
        y = 3.5
        c = cards[4 + i]
        add_rounded_rect(slide, Inches(x), Inches(y), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=c[2])
        add_text(slide, "⚠", Inches(x + 0.05), Inches(y + 0.08), Inches(0.3), Inches(0.3),
                 font_size=16, color=c[2])
        add_text(slide, c[0], Inches(x + 0.1), Inches(y + 0.35), Inches(card_w - 0.2), Inches(0.55),
                 font_size=12, color=TEXT_WHITE, bold=True)
        add_text(slide, c[1], Inches(x + 0.1), Inches(y + 0.9), Inches(card_w - 0.2), Inches(0.65),
                 font_size=9, color=TEXT_LIGHT)
    
    # Right side: Packet flow summary
    add_rounded_rect(slide, Inches(7.8), Inches(1.6), Inches(5.0), Inches(3.55),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "PACKET → DETECTION FLOW", Inches(8.0), Inches(1.7), Inches(4.6), Inches(0.3),
             font_size=13, color=ACCENT_CYAN, bold=True)
    
    flow_items = [
        "ARP Packet Received",
        "   ↓",
        "Extract: src_ip, src_mac, dst_ip, dst_mac, op",
        "   ↓",
        "Update ARP Table State",
        "   ↓",
        "Run All 7 Rules Against Packet + Context",
        "   ↓",
        "Collect Alerts (rule, severity, reason)",
        "   ↓",
        "Return Alert List to Pipeline",
    ]
    for i, item in enumerate(flow_items):
        color = ACCENT_CYAN if "↓" in item else TEXT_LIGHT
        if "Run All" in item:
            color = ACCENT_BLUE
            bold = True
        elif "Alert" in item and "↓" not in item:
            color = ACCENT_AMBER
            bold = True
        else:
            bold = False
        add_text(slide, item, Inches(8.0), Inches(2.1 + i * 0.27), Inches(4.6), Inches(0.25),
                 font_size=9, color=color, bold=bold)
    
    # Bottom note
    add_text(slide, "All detection rules are defined in detection/arp-detection/detection_engine/rules/",
             Inches(0.6), Inches(5.5), Inches(12), Inches(0.3),
             font_size=9, color=TEXT_DIM)


def slide_06_packet_to_alert(prs):
    """SLIDE 6 — FROM PACKET TO ALERT"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "FROM PACKET TO ALERT", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Simulated packet visualization (left)
    add_rounded_rect(slide, Inches(0.5), Inches(1.3), Inches(4.5), Inches(4.5),
                     fill_color=BG_CARD, line_color=ACCENT_CYAN)
    add_text(slide, "ARP REPLY PACKET", Inches(0.7), Inches(1.4), Inches(4.1), Inches(0.3),
             font_size=13, color=ACCENT_CYAN, bold=True)
    
    packet_fields = [
        ("Sender IP:", "192.168.1.1", ACCENT_RED),
        ("Sender MAC:", "de:ad:be:ef:00:01", ACCENT_RED),
        ("Target IP:", "192.168.1.10", TEXT_LIGHT),
        ("Target MAC:", "00:11:22:33:44:10", TEXT_LIGHT),
        ("Operation:", "REPLY", TEXT_LIGHT),
        ("Timestamp:", "2026-10-07T12:08:14", TEXT_DIM),
    ]
    
    for i, (field, value, color) in enumerate(packet_fields):
        y = 1.9 + i * 0.45
        add_text(slide, field, Inches(0.8), Inches(y), Inches(1.5), Inches(0.3),
                 font_size=10, color=TEXT_DIM, bold=True)
        add_text(slide, value, Inches(2.3), Inches(y), Inches(2.5), Inches(0.3),
                 font_size=11, color=color, font_name="Consolas")
    
    # Baseline comparison
    add_shape(slide, Inches(0.7), Inches(4.5), Inches(4.1), Pt(1), fill_color=DIVIDER_COLOR)
    add_text(slide, "TRUSTED BASELINE:", Inches(0.8), Inches(4.6), Inches(3.8), Inches(0.25),
             font_size=9, color=ACCENT_AMBER, bold=True)
    add_text(slide, '192.168.1.1 → aa:bb:cc:dd:ee:01  (gateway)', Inches(0.8), Inches(4.85), Inches(3.8), Inches(0.25),
             font_size=9, color=ACCENT_GREEN, font_name="Consolas")
    add_text(slide, "❌ MISMATCH: de:ad:be:ef:00:01 ≠ aa:bb:cc:dd:ee:01",
             Inches(0.8), Inches(5.15), Inches(3.8), Inches(0.25),
             font_size=9, color=ACCENT_RED, bold=True, font_name="Consolas")
    
    # Right: Alert pipeline
    pipeline_steps = [
        ("EXTRACT FIELDS", "Parse sender/target IP, MAC, operation, timestamp", ACCENT_CYAN),
        ("UPDATE ARP TABLE", "Record latest IP-MAC observation", ACCENT_BLUE),
        ("COMPARE WITH BASELINE", "Check against config/trusted_baseline.json", ACCENT_BLUE),
        ("VIOLATION DETECTED", "gateway_rule.check → Non-gateway MAC claimed gateway IP", ACCENT_RED),
        ("CLASSIFY SEVERITY", "Critical — Gateway impersonation attempt", ACCENT_RED),
        ("GENERATE ALERT", "Event logged with rule, severity, reason, timestamp", ACCENT_AMBER),
    ]
    
    for i, (step, desc, color) in enumerate(pipeline_steps):
        y = 1.3 + i * 0.85
        add_rounded_rect(slide, Inches(5.5), Inches(y), Inches(7.2), Inches(0.65),
                         fill_color=BG_CARD, line_color=color)
        # Step number
        add_shape(slide, Inches(5.65), Inches(y + 0.12), Inches(0.4), Inches(0.4),
                  fill_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, str(i + 1), Inches(5.65), Inches(y + 0.12), Inches(0.4), Inches(0.4),
                 font_size=14, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        add_text(slide, step, Inches(6.2), Inches(y + 0.05), Inches(6.3), Inches(0.3),
                 font_size=11, color=color, bold=True)
        add_text(slide, desc, Inches(6.2), Inches(y + 0.35), Inches(6.3), Inches(0.25),
                 font_size=9, color=TEXT_DIM)
        
        if i < len(pipeline_steps) - 1:
            add_arrow_down(slide, Inches(5.85), Inches(y + 0.65), Inches(0.15), color)


def slide_07_attacker_id(prs):
    """SLIDE 7 — ATTACKER IDENTIFICATION"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "ATTACKER IDENTIFICATION", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Normal mapping (left)
    add_rounded_rect(slide, Inches(0.6), Inches(1.3), Inches(3.8), Inches(2.8),
                     fill_color=BG_CARD, line_color=ACCENT_GREEN)
    add_text(slide, "✓  LEGITIMATE MAPPING", Inches(0.8), Inches(1.4), Inches(3.4), Inches(0.3),
             font_size=13, color=ACCENT_GREEN, bold=True)
    add_multiline_text(slide, [
        ("Gateway IP:", 11, TEXT_DIM, True),
        ("192.168.1.1", 18, ACCENT_GREEN, True),
        ("", 6),
        ("Gateway MAC:", 11, TEXT_DIM, True),
        ("aa:bb:cc:dd:ee:01", 14, ACCENT_GREEN, False),
    ], Inches(0.8), Inches(1.8), Inches(3.4), Inches(2.0),
    font_name="Consolas", alignment=PP_ALIGN.CENTER)
    
    # VS indicator
    add_shape(slide, Inches(4.7), Inches(2.2), Inches(1.0), Inches(1.0),
              fill_color=ACCENT_RED, shape=MSO_SHAPE.OVAL)
    add_text(slide, "VS", Inches(4.7), Inches(2.2), Inches(1.0), Inches(1.0),
             font_size=20, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
    
    # Suspicious mapping (right)
    add_rounded_rect(slide, Inches(6.0), Inches(1.3), Inches(3.8), Inches(2.8),
                     fill_color=RGBColor(0x2A, 0x10, 0x10), line_color=ACCENT_RED)
    add_text(slide, "⚠  SUSPICIOUS MAPPING", Inches(6.2), Inches(1.4), Inches(3.4), Inches(0.3),
             font_size=13, color=ACCENT_RED, bold=True)
    add_multiline_text(slide, [
        ("Gateway IP:", 11, TEXT_DIM, True),
        ("192.168.1.1", 18, ACCENT_RED, True),
        ("", 6),
        ("Attacker MAC:", 11, TEXT_DIM, True),
        ("d6:70:e5:8e:03:51", 14, ACCENT_RED, False),
    ], Inches(6.2), Inches(1.8), Inches(3.4), Inches(2.0),
    font_name="Consolas", alignment=PP_ALIGN.CENTER)
    
    # Alert detail card
    add_rounded_rect(slide, Inches(0.6), Inches(4.5), Inches(9.2), Inches(2.4),
                     fill_color=BG_CARD, line_color=ACCENT_RED)
    add_text(slide, "DETECTION ALERT", Inches(0.8), Inches(4.6), Inches(8.8), Inches(0.3),
             font_size=14, color=ACCENT_RED, bold=True)
    
    alert_fields = [
        ("Rule:", "gateway_impersonation"),
        ("Severity:", "CRITICAL"),
        ("Reason:", "Non-gateway MAC claimed gateway IP in ARP reply"),
        ("Attacker IP:", "192.168.1.1"),
        ("Attacker MAC:", "d6:70:e5:8e:03:51"),
        ("Action:", "ISOLATE_DEVICE"),
    ]
    for i, (field, value) in enumerate(alert_fields):
        row = i % 3
        col = i // 3
        x = 0.8 + col * 4.6
        y = 5.0 + row * 0.5
        val_color = ACCENT_RED if "CRITICAL" in value or "ISOLATE" in value else ACCENT_CYAN
        add_text(slide, field, Inches(x), Inches(y), Inches(1.5), Inches(0.3),
                 font_size=10, color=TEXT_DIM, bold=True)
        add_text(slide, value, Inches(x + 1.2), Inches(y), Inches(3.2), Inches(0.3),
                 font_size=10, color=val_color, font_name="Consolas")


def slide_08_ddos_impact(prs):
    """SLIDE 8 — DDoS / DoS IMPACT ANALYSIS"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "DDoS / DoS IMPACT ANALYSIS", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Timeline (horizontal)
    phases = [
        ("NORMAL\nTRAFFIC", ACCENT_GREEN),
        ("ABNORMAL\nARP ACTIVITY", ACCENT_AMBER),
        ("NETWORK\nDISRUPTION", ACCENT_RED),
        ("DETECTION", ACCENT_BLUE),
        ("MITIGATION", ACCENT_CYAN),
        ("RECOVERY", ACCENT_GREEN),
    ]
    
    box_w = 1.6
    for i, (label, color) in enumerate(phases):
        x = 0.5 + i * (box_w + 0.35)
        add_rounded_rect(slide, Inches(x), Inches(1.3), Inches(box_w), Inches(0.65),
                         fill_color=BG_CARD, line_color=color)
        add_text(slide, label, Inches(x), Inches(1.3), Inches(box_w), Inches(0.65),
                 font_size=9, color=color, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        if i < len(phases) - 1:
            add_arrow_right(slide, Inches(x + box_w), Inches(1.63), Inches(0.3), color)
    
    # Impact metrics cards
    metrics = [
        ("0.48 pps", "NORMAL\nARP RATE", ACCENT_GREEN),
        ("9.24 pps", "ATTACK\nARP RATE", ACCENT_RED),
        ("1825%", "RATE\nINCREASE", ACCENT_RED),
        ("8", "AFFECTED\nHOSTS", ACCENT_AMBER),
        ("24.67s", "ATTACK\nDURATION", ACCENT_AMBER),
    ]
    
    card_w = 2.2
    for i, (value, label, color) in enumerate(metrics):
        x = 0.5 + i * (card_w + 0.2)
        add_kpi_card(slide, Inches(x), Inches(2.4), Inches(card_w), Inches(1.4), value, label, color)
    
    # Disruption indicator
    add_rounded_rect(slide, Inches(0.5), Inches(4.1), Inches(5.5), Inches(1.4),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "PRE-MITIGATION DISRUPTION INDEX", Inches(0.7), Inches(4.2), Inches(5.1), Inches(0.3),
             font_size=11, color=TEXT_DIM, bold=True)
    # Progress bar
    bar_w = 5.1
    add_rounded_rect(slide, Inches(0.7), Inches(4.6), Inches(bar_w), Inches(0.4),
                     fill_color=RGBColor(0x1E, 0x1E, 0x2E))
    add_rounded_rect(slide, Inches(0.7), Inches(4.6), Inches(bar_w * 0.5727), Inches(0.4),
                     fill_color=ACCENT_RED)
    add_text(slide, "0.5727", Inches(0.7), Inches(4.6), Inches(bar_w * 0.5727), Inches(0.4),
             font_size=14, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)
    
    # Right: Traffic comparison
    add_rounded_rect(slide, Inches(6.3), Inches(4.1), Inches(6.5), Inches(1.4),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "TRAFFIC COMPARISON", Inches(6.5), Inches(4.2), Inches(6.1), Inches(0.25),
             font_size=11, color=ACCENT_CYAN, bold=True)
    
    comparisons = [
        ("Total Packets:", "60 normal  /  228 abnormal"),
        ("Request:Reply:", "1:1 normal  /  3.38:1 abnormal"),
        ("IP-MAC Conflicts:", "0 normal  /  4 abnormal"),
        ("Unique Source MACs:", "7 normal  /  15 abnormal"),
    ]
    for i, (label, value) in enumerate(comparisons):
        y = 4.55 + i * 0.22
        add_text(slide, label, Inches(6.5), Inches(y), Inches(2.0), Inches(0.2),
                 font_size=8, color=TEXT_DIM, bold=True)
        add_text(slide, value, Inches(8.5), Inches(y), Inches(4.1), Inches(0.2),
                 font_size=8, color=TEXT_LIGHT, font_name="Consolas")
    
    # Important callout at bottom
    add_rounded_rect(slide, Inches(0.5), Inches(5.8), Inches(12.3), Inches(1.0),
                     fill_color=RGBColor(0x1A, 0x18, 0x10), line_color=ACCENT_AMBER)
    add_text(slide, "⚠  IMPORTANT DISTINCTION", Inches(0.7), Inches(5.9), Inches(11.9), Inches(0.25),
             font_size=11, color=ACCENT_AMBER, bold=True)
    add_text(slide, "ARP spoofing ≠ DDoS.  ARP spoofing can contribute to network disruption and DoS conditions. "
             "This module evaluates the network-disruption impact of ARP spoofing activity, not DDoS attribution.",
             Inches(0.7), Inches(6.2), Inches(11.9), Inches(0.5),
             font_size=9, color=TEXT_LIGHT)


def slide_09_prevention(prs):
    """SLIDE 9 — PREVENTION & MITIGATION"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "PREVENTION & MITIGATION", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    add_text(slide, "SOC-Style Incident Response Pipeline", Inches(0.6), Inches(1.0), Inches(8), Inches(0.3),
             font_size=12, color=TEXT_DIM)
    
    # Vertical incident response pipeline (center)
    ir_steps = [
        ("DETECTION", "Rule engine identifies ARP anomaly", ACCENT_BLUE),
        ("ALERT", "Event logged with severity + reason", ACCENT_AMBER),
        ("RISK ASSESSMENT", "Combine rule score → LOW / MEDIUM / HIGH / CRITICAL", ACCENT_AMBER),
        ("RESPONSE REQUEST", "Generate ISOLATE_DEVICE request", ACCENT_RED),
        ("ADMIN APPROVAL", "Administrator approves the response action", TEXT_WHITE),
        ("EXECUTE MITIGATION", "Block attacker MAC/IP via OS firewall rules", ACCENT_RED),
        ("MONITOR", "Continue monitoring for further suspicious activity", ACCENT_CYAN),
        ("RECOVERY", "Broadcast corrective Gratuitous ARP to restore mappings", ACCENT_GREEN),
    ]
    
    step_w = 6.0
    step_h = 0.52
    gap = 0.1
    start_x = 3.7
    
    for i, (label, desc, color) in enumerate(ir_steps):
        y = 1.5 + i * (step_h + gap)
        add_rounded_rect(slide, Inches(start_x), Inches(y), Inches(step_w), Inches(step_h),
                         fill_color=BG_CARD, line_color=color)
        # Step circle
        add_shape(slide, Inches(start_x + 0.08), Inches(y + 0.08), Inches(0.36), Inches(0.36),
                  fill_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, str(i + 1), Inches(start_x + 0.08), Inches(y + 0.08), Inches(0.36), Inches(0.36),
                 font_size=12, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        add_text(slide, label, Inches(start_x + 0.55), Inches(y + 0.02), Inches(1.8), Inches(0.25),
                 font_size=10, color=color, bold=True)
        add_text(slide, desc, Inches(start_x + 2.4), Inches(y + 0.02), Inches(3.4), Inches(0.45),
                 font_size=9, color=TEXT_LIGHT, anchor=MSO_ANCHOR.MIDDLE)
        if i < len(ir_steps) - 1:
            add_arrow_down(slide, Inches(start_x + 0.26), Inches(y + step_h), Inches(gap), color)
    
    # Left side: Key action highlight
    add_rounded_rect(slide, Inches(0.5), Inches(1.5), Inches(2.8), Inches(3.0),
                     fill_color=RGBColor(0x2A, 0x10, 0x10), line_color=ACCENT_RED)
    add_text(slide, "PRIMARY ACTION", Inches(0.6), Inches(1.6), Inches(2.6), Inches(0.3),
             font_size=11, color=ACCENT_RED, bold=True)
    add_text(slide, "ISOLATE\n_DEVICE", Inches(0.6), Inches(2.0), Inches(2.6), Inches(1.0),
             font_size=28, color=ACCENT_RED, bold=True, alignment=PP_ALIGN.CENTER,
             font_name="Consolas")
    add_text(slide, "Block attacking MAC/IP\nvia OS-level firewall rules\n(iptables / Windows Firewall)",
             Inches(0.6), Inches(3.2), Inches(2.6), Inches(1.0),
             font_size=9, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
    
    # Risk score model
    add_rounded_rect(slide, Inches(0.5), Inches(4.8), Inches(2.8), Inches(1.7),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "RISK SCORING", Inches(0.6), Inches(4.9), Inches(2.6), Inches(0.25),
             font_size=11, color=ACCENT_AMBER, bold=True)
    risk_levels = [
        ("0–24", "LOW", ACCENT_GREEN),
        ("25–49", "MEDIUM", ACCENT_AMBER),
        ("50–74", "HIGH", ACCENT_RED),
        ("75–100", "CRITICAL", ACCENT_RED),
    ]
    for i, (score, level, color) in enumerate(risk_levels):
        y = 5.25 + i * 0.28
        add_text(slide, score, Inches(0.7), Inches(y), Inches(0.8), Inches(0.25),
                 font_size=9, color=TEXT_DIM, font_name="Consolas")
        add_text(slide, level, Inches(1.5), Inches(y), Inches(1.5), Inches(0.25),
                 font_size=10, color=color, bold=True)


def slide_10_tech_stack(prs):
    """SLIDE 10 — TECHNOLOGY STACK"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "TECHNOLOGY STACK", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    techs = [
        ("CORE", "Python 3", "Primary language for\nall modules", ACCENT_CYAN),
        ("NETWORK", "Scapy", "Real-time ARP packet\ncapture & parsing", ACCENT_BLUE),
        ("BACKEND", "Flask", "RESTful API server\n& route handling", ACCENT_BLUE),
        ("DATABASE", "SQLite", "Persistent storage via\nFlask-SQLAlchemy", ACCENT_GREEN),
        ("FRONTEND", "Jinja / HTML\nCSS / JS", "Dashboard templates\n& live UI", ACCENT_CYAN),
        ("TESTING", "pytest\nunittest", "Automated test suite\n& evaluation", ACCENT_AMBER),
    ]
    
    card_w = 1.9
    card_h = 2.8
    gap = 0.15
    start_x = 0.5
    
    for i, (category, tech, desc, color) in enumerate(techs):
        x = start_x + i * (card_w + gap)
        add_rounded_rect(slide, Inches(x), Inches(1.4), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=color)
        # Category label
        add_shape(slide, Inches(x), Inches(1.4), Inches(card_w), Inches(0.4), fill_color=color)
        add_text(slide, category, Inches(x), Inches(1.4), Inches(card_w), Inches(0.4),
                 font_size=10, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Technology name
        add_text(slide, tech, Inches(x + 0.1), Inches(2.0), Inches(card_w - 0.2), Inches(0.8),
                 font_size=18, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER)
        # Description
        add_text(slide, desc, Inches(x + 0.1), Inches(2.9), Inches(card_w - 0.2), Inches(0.8),
                 font_size=9, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
    
    # No ML Extension on this slide anymore


def slide_11_testing(prs):
    """SLIDE 11 — TESTING STRATEGY"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "TESTING STRATEGY", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    add_text(slide, "6 controlled scenarios  ·  288 synthetic packets  ·  Automated evaluation pipeline",
             Inches(0.6), Inches(1.0), Inches(10), Inches(0.3),
             font_size=12, color=TEXT_DIM)
    
    # Scenario matrix
    scenarios = [
        ("NORMAL TRAFFIC", "60 pkts", "No alert", "NONE", "FAIL (FP)", "20", ACCENT_AMBER, "Baseline mismatch with test fixture"),
        ("IP-MAC CONFLICT", "35 pkts", "Detection", "MEDIUM", "PASS", "52", ACCENT_GREEN, "Known IP → unexpected MAC"),
        ("GATEWAY SPOOFING", "25 pkts", "Detection", "CRITICAL", "PASS", "46", ACCENT_GREEN, "Non-gateway MAC claimed gateway IP"),
        ("DUPLICATE IP", "11 pkts", "Detection", "HIGH", "PASS", "15", ACCENT_GREEN, "Multiple MACs claim same IP"),
        ("SUSPICIOUS REPLIES", "27 pkts", "Detection", "MEDIUM", "PASS", "21", ACCENT_GREEN, "Unsolicited gratuitous ARP"),
        ("HIGH ARP RATE", "130 pkts", "Detection", "HIGH", "PASS", "73", ACCENT_GREEN, "Abnormal ARP flood rate"),
    ]
    
    # Header
    headers = ["SCENARIO", "PACKETS", "EXPECTED", "SEVERITY", "RESULT", "EVENTS", "DESCRIPTION"]
    widths = [2.0, 0.8, 0.9, 1.0, 0.9, 0.8, 5.2]
    x_start = 0.5
    
    for j, (header, w) in enumerate(zip(headers, widths)):
        x = x_start + sum(widths[:j])
        add_text(slide, header, Inches(x), Inches(1.5), Inches(w), Inches(0.35),
                 font_size=8, color=ACCENT_CYAN, bold=True, alignment=PP_ALIGN.CENTER)
    
    add_shape(slide, Inches(0.5), Inches(1.85), Inches(sum(widths)), Pt(1), fill_color=ACCENT_CYAN)
    
    for i, (name, pkts, expected, severity, result, events, status_color, desc) in enumerate(scenarios):
        y = 2.0 + i * 0.75
        # Alternating row bg
        if i % 2 == 0:
            add_shape(slide, Inches(0.5), Inches(y), Inches(sum(widths)), Inches(0.65),
                      fill_color=BG_CARD)
        
        values = [name, pkts, expected, severity, result, events, desc]
        colors = [TEXT_WHITE, TEXT_LIGHT, TEXT_LIGHT, 
                  ACCENT_RED if severity == "CRITICAL" else ACCENT_AMBER,
                  status_color, ACCENT_CYAN, TEXT_DIM]
        bolds = [True, False, False, True, True, True, False]
        sizes = [9, 9, 9, 9, 10, 10, 8]
        
        for j, (val, w) in enumerate(zip(values, widths)):
            x = x_start + sum(widths[:j])
            add_text(slide, val, Inches(x), Inches(y + 0.05), Inches(w), Inches(0.55),
                     font_size=sizes[j], color=colors[j], bold=bolds[j], alignment=PP_ALIGN.CENTER,
                     anchor=MSO_ANCHOR.MIDDLE)
    
    # Bottom note
    add_text(slide, "⚠  The Normal Traffic scenario FAIL is due to the test fixture using MAC addresses not present in the trusted baseline configuration, "
             "producing expected false positives.",
             Inches(0.5), Inches(6.6), Inches(12.3), Inches(0.5),
             font_size=8, color=ACCENT_AMBER)


def slide_12_results(prs):
    """SLIDE 12 — FINAL RESULTS (KPI cards)"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "FINAL RESULTS & PERFORMANCE", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Large KPI cards — top row
    kpis = [
        ("100%", "DETECTION RATE\n(RECALL)", ACCENT_GREEN),
        ("83.33%", "PRECISION", ACCENT_CYAN),
        ("90.91%", "F1 SCORE", ACCENT_CYAN),
        ("1.96 ms", "AVG DETECTION\nLATENCY", ACCENT_BLUE),
    ]
    
    card_w = 2.8
    gap = 0.25
    start_x = 0.5
    
    for i, (value, label, color) in enumerate(kpis):
        x = start_x + i * (card_w + gap)
        add_rounded_rect(slide, Inches(x), Inches(1.2), Inches(card_w), Inches(1.8),
                         fill_color=BG_CARD, line_color=color)
        add_text(slide, value, Inches(x), Inches(1.35), Inches(card_w), Inches(0.9),
                 font_size=42, color=color, bold=True, alignment=PP_ALIGN.CENTER)
        add_text(slide, label, Inches(x), Inches(2.3), Inches(card_w), Inches(0.5),
                 font_size=10, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)
    
    # Secondary metrics row
    secondary = [
        ("ACCURACY", "83.33%", ACCENT_CYAN),
        ("FNR", "0.00%", ACCENT_GREEN),
        ("FPR", "100.00%", ACCENT_AMBER),
        ("TP", "5", ACCENT_GREEN),
        ("TN", "0", TEXT_DIM),
        ("FP", "1", ACCENT_AMBER),
        ("FN", "0", ACCENT_GREEN),
    ]
    
    sec_w = 1.6
    sec_gap = 0.12
    for i, (label, value, color) in enumerate(secondary):
        x = 0.5 + i * (sec_w + sec_gap)
        add_rounded_rect(slide, Inches(x), Inches(3.3), Inches(sec_w), Inches(0.9),
                         fill_color=BG_CARD, line_color=DIVIDER_COLOR)
        add_text(slide, label, Inches(x), Inches(3.35), Inches(sec_w), Inches(0.3),
                 font_size=8, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)
        add_text(slide, value, Inches(x), Inches(3.6), Inches(sec_w), Inches(0.5),
                 font_size=18, color=color, bold=True, alignment=PP_ALIGN.CENTER)
    
    # Latency detail
    add_rounded_rect(slide, Inches(0.5), Inches(4.5), Inches(5.5), Inches(1.2),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "DETECTION LATENCY BREAKDOWN", Inches(0.7), Inches(4.6), Inches(5.1), Inches(0.25),
             font_size=11, color=ACCENT_BLUE, bold=True)
    latency_items = [
        ("Minimum:", "0.54 ms"),
        ("Average:", "1.96 ms"),
        ("Median:", "1.15 ms"),
        ("Maximum:", "5.83 ms"),
        ("Std Dev:", "2.19 ms"),
    ]
    for i, (label, value) in enumerate(latency_items):
        x = 0.7 + (i % 3) * 1.8
        y = 4.95 + (i // 3) * 0.3
        add_text(slide, label, Inches(x), Inches(y), Inches(0.9), Inches(0.25),
                 font_size=9, color=TEXT_DIM)
        add_text(slide, value, Inches(x + 0.85), Inches(y), Inches(0.9), Inches(0.25),
                 font_size=9, color=ACCENT_CYAN, bold=True, font_name="Consolas")
    
    # DDoS summary
    add_rounded_rect(slide, Inches(6.3), Inches(4.5), Inches(6.2), Inches(1.2),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "DDoS IMPACT VALIDATION", Inches(6.5), Inches(4.6), Inches(5.8), Inches(0.25),
             font_size=11, color=ACCENT_RED, bold=True)
    add_multiline_text(slide, [
        ("ARP rate increased 19.2x during attack (0.48 → 9.24 pps)", 9, TEXT_LIGHT, False),
        ("IP-MAC conflicts: 0 → 4 during active spoofing", 9, TEXT_LIGHT, False),
        ("Unique source MACs: 7 → 15 (forged MAC addresses)", 9, TEXT_LIGHT, False),
    ], Inches(6.5), Inches(4.95), Inches(5.8), Inches(0.7))
    
    # Evaluation limitation note
    add_rounded_rect(slide, Inches(0.5), Inches(6.0), Inches(12.0), Inches(0.7),
                     fill_color=RGBColor(0x1A, 0x18, 0x10), line_color=ACCENT_AMBER)
    add_text(slide, "⚠  Evaluation Limitation:", Inches(0.7), Inches(6.05), Inches(11.6), Inches(0.25),
             font_size=9, color=ACCENT_AMBER, bold=True)
    add_text(slide, "Normal traffic test fixture used MAC addresses not present in the configured trusted baseline (trusted_baseline.json), "
             "producing false positives. This is an expected artifact of the strict baseline enforcement and synthetic test data.",
             Inches(0.7), Inches(6.3), Inches(11.6), Inches(0.35),
             font_size=8, color=TEXT_LIGHT)


def slide_13_charts(prs):
    """SLIDE 13 — PERFORMANCE VISUALIZATION (charts from evaluation)"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "PERFORMANCE VISUALIZATION", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    
    # Insert actual charts from final_evaluation/
    chart_dir = os.path.join(os.path.dirname(__file__), "final_evaluation")
    
    charts = [
        ("chart_confusion_matrix.png", 0.3, 1.2, 4.0, 3.0),
        ("chart_events_by_scenario.png", 4.5, 1.2, 4.2, 3.0),
        ("chart_detection_latency.png", 8.9, 1.2, 4.2, 3.0),
        ("chart_arp_rate_comparison.png", 0.3, 4.4, 4.0, 3.0),
        ("chart_mitigation_comparison.png", 4.5, 4.4, 4.2, 3.0),
    ]
    
    inserted = 0
    for chart_name, x, y, w, h in charts:
        chart_path = os.path.join(chart_dir, chart_name)
        if os.path.exists(chart_path):
            # Dark background card behind chart
            add_rounded_rect(slide, Inches(x - 0.05), Inches(y - 0.05), Inches(w + 0.1), Inches(h + 0.1),
                             fill_color=BG_CARD, line_color=DIVIDER_COLOR)
            slide.shapes.add_picture(chart_path, Inches(x), Inches(y), Inches(w), Inches(h))
            inserted += 1
        else:
            add_rounded_rect(slide, Inches(x), Inches(y), Inches(w), Inches(h),
                             fill_color=BG_CARD, line_color=DIVIDER_COLOR)
            add_text(slide, f"[Chart: {chart_name}]", Inches(x), Inches(y), Inches(w), Inches(h),
                     font_size=10, color=TEXT_DIM, alignment=PP_ALIGN.CENTER,
                     anchor=MSO_ANCHOR.MIDDLE)
    
    # Label for bottom-right
    add_text(slide, "All charts generated from actual evaluation data  ·  Synthetic controlled test environment",
             Inches(8.9), Inches(4.6), Inches(4.2), Inches(0.5),
             font_size=8, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)
    
    return inserted


def slide_14_dashboard(prs):
    """SLIDE 14 — DASHBOARD / DEPLOYED SYSTEM"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "SECURITY DASHBOARD", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    add_text(slide, "Flask + Jinja + SQLite  ·  Real-time web interface for network administrators",
             Inches(0.6), Inches(1.0), Inches(10), Inches(0.3),
             font_size=12, color=TEXT_DIM)
    
    # Dashboard pages as cards
    pages = [
        ("OVERVIEW", "Network status metrics,\nconnected devices, system health,\nactive alerts count", ACCENT_CYAN, "overview.html"),
        ("ALERTS", "Real-time alert feed with\nseverity classification,\ntimestamps, and source data", ACCENT_RED, "alerts.html"),
        ("DEVICES", "Known device registry,\nIP-MAC mappings,\ndevice status tracking", ACCENT_GREEN, "devices.html"),
        ("INCIDENTS", "Historical incident log\nwith full event details\nand investigation data", ACCENT_AMBER, "incidents.html"),
        ("IMPACT", "DDoS/DoS impact metrics,\ntraffic rate analysis,\ndisruption indicators", ACCENT_RED, "impact.html"),
        ("MITIGATION", "Response action history,\nisolation status,\nfirewall rule tracking", ACCENT_BLUE, "mitigation.html"),
        ("RECOVERY", "Network restoration status,\ncorrective ARP broadcasts,\nrecovery verification", ACCENT_GREEN, "recovery.html"),
        ("ARP TRAFFIC", "Live ARP packet monitoring,\nrequest/reply breakdown,\ntraffic visualization", ACCENT_CYAN, "arp.html"),
    ]
    
    card_w = 2.85
    card_h = 2.0
    gap = 0.2
    
    for i, (title, desc, color, template) in enumerate(pages):
        col = i % 4
        row = i // 4
        x = 0.5 + col * (card_w + gap)
        y = 1.5 + row * (card_h + gap)
        
        add_rounded_rect(slide, Inches(x), Inches(y), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=color)
        # Color header bar
        add_shape(slide, Inches(x), Inches(y), Inches(card_w), Inches(0.35), fill_color=color)
        add_text(slide, title, Inches(x), Inches(y), Inches(card_w), Inches(0.35),
                 font_size=11, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Description
        add_text(slide, desc, Inches(x + 0.1), Inches(y + 0.5), Inches(card_w - 0.2), Inches(1.0),
                 font_size=9, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
        # Template file
        add_text(slide, template, Inches(x + 0.1), Inches(y + card_h - 0.35), Inches(card_w - 0.2), Inches(0.25),
                 font_size=7, color=TEXT_DIM, alignment=PP_ALIGN.CENTER, font_name="Consolas")
    
    # API info at bottom
    add_rounded_rect(slide, Inches(0.5), Inches(5.9), Inches(12.3), Inches(0.8),
                     fill_color=BG_CARD, line_color=DIVIDER_COLOR)
    add_text(slide, "8 RESTful API Blueprints  ·  8 Dashboard Pages  ·  8 SQLAlchemy Models  ·  Served at http://127.0.0.1:5000",
             Inches(0.5), Inches(5.9), Inches(12.3), Inches(0.8),
             font_size=11, color=ACCENT_CYAN, alignment=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE)


def slide_15_e2e_workflow(prs):
    """SLIDE 15 — END-TO-END WORKFLOW"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "END-TO-END INCIDENT WORKFLOW", Inches(0.6), Inches(0.3), Inches(8), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(2.5))
    add_text(slide, "Proving full integration from ARP packet capture to dashboard visualization",
             Inches(0.6), Inches(1.0), Inches(10), Inches(0.3),
             font_size=12, color=TEXT_DIM)
    
    # Large horizontal workflow
    steps = [
        ("ARP PACKET\nCAPTURED", "Scapy sniffs\npacket on wire", ACCENT_CYAN, "network/"),
        ("RULES\nEVALUATED", "7 detection rules\nchecked in sequence", ACCENT_BLUE, "detection/"),
        ("ALERT\nGENERATED", "Severity + reason\nassigned to event", ACCENT_AMBER, "detection_engine/"),
        ("ATTACKER\nIDENTIFIED", "Source MAC/IP\npinpointed", ACCENT_AMBER, "detection_engine/"),
        ("IMPACT\nANALYZED", "DDoS/DoS metrics\ncalculated", ACCENT_RED, "testing/evaluation/"),
        ("DEVICE\nISOLATED", "Firewall rule\nexecuted", ACCENT_RED, "prevention/"),
        ("NETWORK\nRECOVERED", "Corrective ARP\nbroadcast", ACCENT_GREEN, "prevention/"),
        ("LOGGED IN\nDASHBOARD", "Persisted in DB\n& visible in UI", ACCENT_GREEN, "backend/"),
    ]
    
    card_w = 1.35
    card_h = 2.5
    gap = 0.15
    start_x = 0.3
    
    for i, (label, desc, color, module) in enumerate(steps):
        x = start_x + i * (card_w + gap)
        y = 1.6
        
        add_rounded_rect(slide, Inches(x), Inches(y), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=color)
        # Step number
        add_shape(slide, Inches(x + card_w/2 - 0.2), Inches(y + 0.12), Inches(0.4), Inches(0.4),
                  fill_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, str(i + 1), Inches(x + card_w/2 - 0.2), Inches(y + 0.12), Inches(0.4), Inches(0.4),
                 font_size=14, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Label
        add_text(slide, label, Inches(x + 0.05), Inches(y + 0.6), Inches(card_w - 0.1), Inches(0.5),
                 font_size=9, color=color, bold=True, alignment=PP_ALIGN.CENTER)
        # Desc
        add_text(slide, desc, Inches(x + 0.05), Inches(y + 1.15), Inches(card_w - 0.1), Inches(0.6),
                 font_size=8, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
        # Module
        add_text(slide, module, Inches(x + 0.05), Inches(y + card_h - 0.35), Inches(card_w - 0.1), Inches(0.25),
                 font_size=7, color=TEXT_DIM, alignment=PP_ALIGN.CENTER, font_name="Consolas")
        
        # Arrow
        if i < len(steps) - 1:
            add_arrow_right(slide, Inches(x + card_w), Inches(y + card_h/2), Inches(gap), color)
    
    # Bottom integration proof
    add_rounded_rect(slide, Inches(0.5), Inches(4.5), Inches(12.3), Inches(1.0),
                     fill_color=BG_CARD, line_color=ACCENT_GREEN)
    add_text(slide, "✓  FULLY INTEGRATED PIPELINE", Inches(0.7), Inches(4.6), Inches(11.9), Inches(0.3),
             font_size=14, color=ACCENT_GREEN, bold=True, alignment=PP_ALIGN.CENTER)
    add_text(slide, "Every module is connected and operational  ·  98 unit tests passing  ·  6 integration scenarios validated  ·  288 synthetic packets processed",
             Inches(0.7), Inches(4.95), Inches(11.9), Inches(0.4),
             font_size=10, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)


def slide_16_team(prs):
    """SLIDE 16 — TEAM CONTRIBUTION"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    add_text(slide, "GROUP 52  ·  TEAM CONTRIBUTIONS", Inches(0.6), Inches(0.3), Inches(10), Inches(0.5),
             font_size=28, color=TEXT_WHITE, bold=True)
    add_accent_line(slide, Inches(0.6), Inches(0.85), Inches(3.0))
    
    team = [
        ("CHINTANIKA M", "23BCY10056", "Network\nMonitoring", "Scapy ARP packet capture,\nnetwork parsing,\npacket extraction", ACCENT_CYAN),
        ("RISHIMA SHARMA", "23BCY10231", "ARP Spoofing\nDetection", "7 rule-based detection rules,\nbaseline validation,\nARPSpoofDetector engine", ACCENT_BLUE),
        ("ANJU KUMARI", "23BCY10267", "Prevention &\nMitigation", "Risk scoring, ISOLATE_DEVICE,\nfirewall integration,\nincident response", ACCENT_AMBER),
        ("AKSHAY SINGH", "23BCY10283", "Testing &\nEvaluation", "6 test scenarios, metrics,\nDDoS impact analysis,\nautomated testing", ACCENT_RED),
        ("OVEIYA K", "23BCY10309", "Backend &\nDashboard", "Flask API, SQLite DB,\n8 dashboard pages,\nJinja templates", ACCENT_GREEN),
    ]
    
    card_w = 2.3
    card_h = 4.0
    gap = 0.2
    start_x = 0.4
    
    for i, (name, reg, role, desc, color) in enumerate(team):
        x = start_x + i * (card_w + gap)
        
        # Card
        add_rounded_rect(slide, Inches(x), Inches(1.3), Inches(card_w), Inches(card_h),
                         fill_color=BG_CARD, line_color=color)
        # Color header
        add_shape(slide, Inches(x), Inches(1.3), Inches(card_w), Inches(0.07), fill_color=color)
        # Avatar circle
        add_shape(slide, Inches(x + card_w/2 - 0.35), Inches(1.6), Inches(0.7), Inches(0.7),
                  fill_color=color, shape=MSO_SHAPE.OVAL)
        add_text(slide, name[0], Inches(x + card_w/2 - 0.35), Inches(1.6), Inches(0.7), Inches(0.7),
                 font_size=22, color=BG_DARK, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        # Name
        add_text(slide, name, Inches(x + 0.05), Inches(2.4), Inches(card_w - 0.1), Inches(0.3),
                 font_size=11, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER)
        # Reg
        add_text(slide, reg, Inches(x + 0.05), Inches(2.7), Inches(card_w - 0.1), Inches(0.25),
                 font_size=8, color=TEXT_DIM, alignment=PP_ALIGN.CENTER, font_name="Consolas")
        # Role
        add_text(slide, role, Inches(x + 0.05), Inches(3.1), Inches(card_w - 0.1), Inches(0.5),
                 font_size=13, color=color, bold=True, alignment=PP_ALIGN.CENTER)
        # Desc
        add_text(slide, desc, Inches(x + 0.1), Inches(3.7), Inches(card_w - 0.2), Inches(1.2),
                 font_size=8, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
    
    # Supervisor
    add_text(slide, "Supervisor:  Dr. Sreevani Maddukuri", Inches(0.5), Inches(5.7), Inches(12.3), Inches(0.3),
             font_size=12, color=ACCENT_CYAN, alignment=PP_ALIGN.CENTER)


def slide_17_conclusion(prs):
    """SLIDE 17 — CONCLUSION / THANK YOU"""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide)
    
    # Subtle grid background
    for i in range(0, 14):
        add_shape(slide, Inches(i), Inches(0), Pt(0.5), SLIDE_H, fill_color=RGBColor(0x12, 0x16, 0x22))
    for i in range(0, 8):
        add_shape(slide, Inches(0), Inches(i), SLIDE_W, Pt(0.5), fill_color=RGBColor(0x12, 0x16, 0x22))
    
    # Shield and title
    add_text(slide, "🛡️", Inches(0), Inches(0.5), SLIDE_W, Inches(0.8),
             font_size=50, alignment=PP_ALIGN.CENTER)
    add_text(slide, "ARPShield", Inches(0), Inches(1.3), SLIDE_W, Inches(0.7),
             font_size=48, color=ACCENT_CYAN, bold=True, alignment=PP_ALIGN.CENTER)
    
    add_accent_line(slide, Inches(5.2), Inches(2.1), Inches(3.0), ACCENT_BLUE)
    
    # Pipeline summary
    pipeline_labels = ["MONITOR", "DETECT", "IDENTIFY", "ANALYZE", "MITIGATE", "RECOVER"]
    pipeline_colors = [ACCENT_CYAN, ACCENT_BLUE, ACCENT_BLUE, ACCENT_AMBER, ACCENT_RED, ACCENT_GREEN]
    
    total_w = 10.0
    box_w = total_w / len(pipeline_labels) - 0.15
    start_x = (13.333 - total_w) / 2
    
    for i, (label, color) in enumerate(zip(pipeline_labels, pipeline_colors)):
        x = start_x + i * (box_w + 0.15)
        add_rounded_rect(slide, Inches(x), Inches(2.5), Inches(box_w), Inches(0.5),
                         fill_color=BG_CARD, line_color=color)
        add_text(slide, label, Inches(x), Inches(2.5), Inches(box_w), Inches(0.5),
                 font_size=11, color=color, bold=True, alignment=PP_ALIGN.CENTER,
                 anchor=MSO_ANCHOR.MIDDLE)
        if i < len(pipeline_labels) - 1:
            add_arrow_right(slide, Inches(x + box_w), Inches(2.75), Inches(0.12), color)
    
    # Main statement
    add_text(slide, "An integrated cybersecurity approach to\nARP spoofing detection and network disruption analysis.",
             Inches(1.5), Inches(3.4), Inches(10.3), Inches(0.8),
             font_size=16, color=TEXT_LIGHT, alignment=PP_ALIGN.CENTER)
    
    # Key achievements
    achievements = [
        ("100%", "Detection Rate"),
        ("90.91%", "F1 Score"),
        ("1.96 ms", "Avg Latency"),
        ("98", "Tests Passing"),
    ]
    
    ach_w = 2.2
    ach_start = (13.333 - len(achievements) * (ach_w + 0.3)) / 2
    for i, (value, label) in enumerate(achievements):
        x = ach_start + i * (ach_w + 0.3)
        add_rounded_rect(slide, Inches(x), Inches(4.3), Inches(ach_w), Inches(0.85),
                         fill_color=BG_CARD, line_color=DIVIDER_COLOR)
        add_text(slide, value, Inches(x), Inches(4.33), Inches(ach_w), Inches(0.4),
                 font_size=20, color=ACCENT_CYAN, bold=True, alignment=PP_ALIGN.CENTER)
        add_text(slide, label, Inches(x), Inches(4.73), Inches(ach_w), Inches(0.3),
                 font_size=9, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)
    
    # Thank you
    add_text(slide, "THANK YOU", Inches(0), Inches(5.5), SLIDE_W, Inches(0.6),
             font_size=32, color=TEXT_WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    add_text(slide, "QUESTIONS?", Inches(0), Inches(6.05), SLIDE_W, Inches(0.4),
             font_size=16, color=ACCENT_CYAN, alignment=PP_ALIGN.CENTER)
    
    # Supervisor
    add_text(slide, "Supervisor:  Dr. Sreevani Maddukuri  ·  VIT Bhopal University  ·  Group 52",
             Inches(0), Inches(6.7), SLIDE_W, Inches(0.3),
             font_size=10, color=TEXT_DIM, alignment=PP_ALIGN.CENTER)


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    prs = Presentation()
    prs.slide_width = Emu(12192000)   # 13.333 inches
    prs.slide_height = Emu(6858000)   # 7.5 inches
    
    # Build all 18 slides
    slide_01_hero(prs)
    slide_02_problem(prs)
    slide_03_what_arpshield_does(prs)
    slide_04_architecture(prs)
    slide_05_detection_engine(prs)
    slide_06_packet_to_alert(prs)
    slide_07_attacker_id(prs)
    slide_08_ddos_impact(prs)
    slide_09_prevention(prs)
    slide_10_tech_stack(prs)
    slide_11_testing(prs)
    slide_12_results(prs)
    charts_inserted = slide_13_charts(prs)
    slide_14_dashboard(prs)
    slide_15_e2e_workflow(prs)
    slide_16_team(prs)
    slide_17_conclusion(prs)
    
    output_dir = os.path.join(os.path.dirname(__file__), "final_evaluation")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "ARPShield_Final_Presentation.pptx")
    
    try:
        prs.save(output_path)
    except PermissionError:
        output_path = os.path.join(output_dir, "ARPShield_Final_Presentation_V3.pptx")
        prs.save(output_path)
    
    print(f"Presentation saved to: {output_path}")
    print(f"Total slides: {len(prs.slides)}")
    print(f"Charts inserted: {charts_inserted}/5")
    print("Done.")


if __name__ == "__main__":
    main()
