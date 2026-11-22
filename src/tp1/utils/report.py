
from fpdf import FPDF


class Report:
    def __init__(self, capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'analyse réseau - TP1"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        parts = [self.title, self.summary, self.array, self.graph]
        return "\n".join(part for part in parts if part)

    def generate(self, param: str) -> None:
        if param == "array":
            counts = self.capture.get_protocol_counts() or {}
            self.array = str(counts)
        elif param == "graph":
            self.graph = "Graphique des volumes par protocole"

    def save(self, filename: str = None) -> None:
        output = filename or self.filename
        counts = self.capture.get_protocol_counts() or {}
        attacks = getattr(self.capture, "attacks", []) or []

        if not isinstance(counts, dict):
            counts = {}

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Titre
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            w=pdf.epw,
            h=12,
            text=self.title,
            new_x="LMARGIN",
            new_y="NEXT",
        )

        # Résumé de l'analyse
        pdf.set_font("Helvetica", size=10)
        for line in self.summary.splitlines():
            safe_line = line.encode("latin-1", "replace").decode("latin-1")
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=pdf.epw, h=6, text=safe_line)

        pdf.ln(5)

        # Tableau des protocoles
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            w=pdf.epw,
            h=9,
            text="Volumes par protocole",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(w=90, h=8, text="Protocole", border=1)
        pdf.cell(
            w=pdf.epw - 90,
            h=8,
            text="Nombre de paquets",
            border=1,
            new_x="LMARGIN",
            new_y="NEXT",
        )

        pdf.set_font("Helvetica", size=10)
        for protocol, count in sorted(counts.items()):
            pdf.set_x(pdf.l_margin)
            pdf.cell(w=90, h=8, text=str(protocol), border=1)
            pdf.cell(
                w=pdf.epw - 90,
                h=8,
                text=str(count),
                border=1,
                new_x="LMARGIN",
                new_y="NEXT",
            )

        pdf.ln(8)

        # Graphique horizontal des volumes
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            w=pdf.epw,
            h=9,
            text="Graphique des volumes par protocole",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        if counts:
            max_count = max(counts.values(), default=1) or 1
            max_bar_width = min(90, pdf.epw - 45)

            pdf.set_font("Helvetica", size=9)

            for protocol, count in sorted(counts.items()):
                if pdf.get_y() > pdf.page_break_trigger - 10:
                    pdf.add_page()

                pdf.set_x(pdf.l_margin)
                pdf.cell(w=28, h=7, text=str(protocol))

                bar_width = max_bar_width * count / max_count
                x = pdf.get_x()
                y = pdf.get_y() + 1

                if bar_width > 0:
                    pdf.rect(x, y, bar_width, 5, style="F")

                pdf.set_xy(x + max_bar_width + 3, y - 1)
                pdf.cell(
                    w=pdf.epw - (x - pdf.l_margin) - max_bar_width - 3,
                    h=7,
                    text=str(count),
                    new_x="LMARGIN",
                    new_y="NEXT",
                )

        pdf.ln(8)

        # Alertes détectées
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            w=pdf.epw,
            h=9,
            text="Attaques detectees",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        pdf.set_font("Helvetica", size=10)

        if attacks:
            for attack in attacks:
                line = (
                    f"{attack.get('type', 'inconnu')} - "
                    f"{attack.get('attacker', 'inconnu')}"
                )
                safe_line = line.encode("latin-1", "replace").decode("latin-1")
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(w=pdf.epw, h=7, text=safe_line)
        else:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                w=pdf.epw,
                h=7,
                text="Aucune attaque detectee par les regles appliquees.",
            )

        # Flag trouvé
        pdf.ln(4)
        flag = getattr(self.capture, "flag", None) or "Non trouve"
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(w=pdf.epw, h=7, text=f"Flag : {flag}")

        # Enregistrement du PDF
        pdf.output(output)
