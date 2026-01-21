"""
HTML report generator for WoodwardCheck.

Provides interactive HTML reports with charts and detailed findings.
"""

from datetime import datetime
from typing import List

from .base import BaseReporter, ReportData
from ..modules.base import Finding
from ..utils.constants import CheckResult, Severity


class HTMLReporter(BaseReporter):
    """HTML format report generator."""

    FILE_EXTENSION = ".html"
    MIME_TYPE = "text/html"

    def generate(self, data: ReportData) -> str:
        """Generate HTML report."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WoodwardCheck Security Audit Report</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header(data)}
        {self._generate_summary(data)}
        {self._generate_findings_section(data)}
        {self._generate_footer(data)}
    </div>
    <script>
        {self._get_scripts()}
    </script>
</body>
</html>"""

    def _get_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        :root {
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #17a2b8;
            --info-color: #6c757d;
            --pass-color: #28a745;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 10px;
        }

        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .header-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 5px;
        }

        .header-item label {
            font-size: 0.8rem;
            opacity: 0.8;
            display: block;
        }

        /* Summary Cards */
        .summary-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .card h3 {
            font-size: 0.9rem;
            color: var(--info-color);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .score-card {
            text-align: center;
        }

        .score-value {
            font-size: 3rem;
            font-weight: bold;
        }

        .score-high { color: var(--pass-color); }
        .score-medium { color: var(--medium-color); }
        .score-low { color: var(--critical-color); }

        /* Severity Bars */
        .severity-bar {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }

        .severity-label {
            width: 80px;
            font-weight: 500;
        }

        .severity-track {
            flex: 1;
            height: 20px;
            background: var(--border-color);
            border-radius: 10px;
            overflow: hidden;
            margin: 0 10px;
        }

        .severity-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.5s ease;
        }

        .severity-count {
            width: 30px;
            text-align: right;
            font-weight: bold;
        }

        .fill-critical { background: var(--critical-color); }
        .fill-high { background: var(--high-color); }
        .fill-medium { background: var(--medium-color); }
        .fill-low { background: var(--low-color); }

        /* Findings */
        .findings-section {
            margin-bottom: 30px;
        }

        .findings-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
        }

        .filter-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s;
        }

        .filter-btn:hover {
            transform: translateY(-2px);
        }

        .filter-btn.active {
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }

        .finding-card {
            background: var(--card-bg);
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            cursor: pointer;
            border-left: 4px solid;
        }

        .finding-header.critical { border-color: var(--critical-color); }
        .finding-header.high { border-color: var(--high-color); }
        .finding-header.medium { border-color: var(--medium-color); }
        .finding-header.low { border-color: var(--low-color); }
        .finding-header.info { border-color: var(--info-color); }
        .finding-header.pass { border-color: var(--pass-color); }

        .finding-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .finding-id {
            background: var(--bg-color);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }

        .badge-critical { background: var(--critical-color); }
        .badge-high { background: var(--high-color); }
        .badge-medium { background: var(--medium-color); }
        .badge-low { background: var(--low-color); }
        .badge-info { background: var(--info-color); }
        .badge-pass { background: var(--pass-color); }

        .finding-content {
            padding: 0 20px 20px;
            display: none;
        }

        .finding-content.expanded {
            display: block;
        }

        .finding-section {
            margin-top: 15px;
        }

        .finding-section h4 {
            font-size: 0.85rem;
            color: var(--info-color);
            margin-bottom: 5px;
            text-transform: uppercase;
        }

        .remediation-box {
            background: #e8f5e9;
            border-left: 3px solid var(--pass-color);
            padding: 15px;
            border-radius: 0 5px 5px 0;
        }

        .evidence-box {
            background: var(--bg-color);
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--info-color);
            font-size: 0.85rem;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.5rem;
            }

            .summary-section {
                grid-template-columns: 1fr;
            }
        }
        """

    def _get_scripts(self) -> str:
        """Get JavaScript for interactivity."""
        return """
        // Toggle finding details
        document.querySelectorAll('.finding-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                content.classList.toggle('expanded');
            });
        });

        // Filter findings
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const filter = btn.dataset.filter;

                // Update active button
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                // Filter findings
                document.querySelectorAll('.finding-card').forEach(card => {
                    if (filter === 'all' || card.dataset.severity === filter || card.dataset.result === filter) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });
        """

    def _generate_header(self, data: ReportData) -> str:
        """Generate report header."""
        target_info = ""
        if data.target:
            target_info = f"""
            <div class="header-item">
                <label>Target</label>
                <span>{data.target.host}:{data.target.port}</span>
            </div>
            <div class="header-item">
                <label>Protocol</label>
                <span>{data.target.protocol}</span>
            </div>
            """
            if data.target.device_model:
                target_info += f"""
                <div class="header-item">
                    <label>Device Model</label>
                    <span>{data.target.device_model}</span>
                </div>
                """

        return f"""
        <header class="header">
            <h1>Security Audit Report</h1>
            <p>WoodwardCheck v{data.tool_version}</p>
            <div class="header-info">
                <div class="header-item">
                    <label>Report ID</label>
                    <span>{data.report_id}</span>
                </div>
                <div class="header-item">
                    <label>Generated</label>
                    <span>{data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                {target_info}
                <div class="header-item">
                    <label>Duration</label>
                    <span>{self._format_duration(data.duration_seconds)}</span>
                </div>
            </div>
        </header>
        """

    def _generate_summary(self, data: ReportData) -> str:
        """Generate summary section."""
        summary = data.summary

        # Determine score class
        if summary.security_score >= 80:
            score_class = "score-high"
        elif summary.security_score >= 50:
            score_class = "score-medium"
        else:
            score_class = "score-low"

        # Calculate percentages for bars
        total = summary.total_checks or 1
        max_findings = max(
            summary.critical_findings,
            summary.high_findings,
            summary.medium_findings,
            summary.low_findings,
            1
        )

        return f"""
        <section class="summary-section">
            <div class="card score-card">
                <h3>Security Score</h3>
                <div class="score-value {score_class}">{summary.security_score:.0f}</div>
                <p>out of 100</p>
            </div>

            <div class="card">
                <h3>Check Results</h3>
                <div style="display: flex; justify-content: space-around; text-align: center;">
                    <div>
                        <div style="font-size: 2rem; color: var(--pass-color);">{summary.checks_passed}</div>
                        <div style="font-size: 0.8rem;">Passed</div>
                    </div>
                    <div>
                        <div style="font-size: 2rem; color: var(--critical-color);">{summary.checks_failed}</div>
                        <div style="font-size: 0.8rem;">Failed</div>
                    </div>
                    <div>
                        <div style="font-size: 2rem; color: var(--medium-color);">{summary.checks_warning}</div>
                        <div style="font-size: 0.8rem;">Warnings</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Findings by Severity</h3>
                <div class="severity-bar">
                    <span class="severity-label" style="color: var(--critical-color);">Critical</span>
                    <div class="severity-track">
                        <div class="severity-fill fill-critical" style="width: {summary.critical_findings / max_findings * 100}%;"></div>
                    </div>
                    <span class="severity-count">{summary.critical_findings}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label" style="color: var(--high-color);">High</span>
                    <div class="severity-track">
                        <div class="severity-fill fill-high" style="width: {summary.high_findings / max_findings * 100}%;"></div>
                    </div>
                    <span class="severity-count">{summary.high_findings}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label" style="color: var(--medium-color);">Medium</span>
                    <div class="severity-track">
                        <div class="severity-fill fill-medium" style="width: {summary.medium_findings / max_findings * 100}%;"></div>
                    </div>
                    <span class="severity-count">{summary.medium_findings}</span>
                </div>
                <div class="severity-bar">
                    <span class="severity-label" style="color: var(--low-color);">Low</span>
                    <div class="severity-track">
                        <div class="severity-fill fill-low" style="width: {summary.low_findings / max_findings * 100}%;"></div>
                    </div>
                    <span class="severity-count">{summary.low_findings}</span>
                </div>
            </div>
        </section>
        """

    def _generate_findings_section(self, data: ReportData) -> str:
        """Generate findings section."""
        findings_html = ""

        # Sort findings by severity (most severe first)
        sorted_findings = sorted(
            data.findings,
            key=lambda f: (f.severity.value, f.result != CheckResult.FAIL),
            reverse=True
        )

        for finding in sorted_findings:
            findings_html += self._generate_finding_card(finding)

        return f"""
        <section class="findings-section">
            <div class="findings-header">
                <h2>Detailed Findings ({len(data.findings)})</h2>
                <div class="filter-buttons">
                    <button class="filter-btn active" data-filter="all" style="background: var(--bg-color);">All</button>
                    <button class="filter-btn" data-filter="FAIL" style="background: var(--critical-color); color: white;">Failed</button>
                    <button class="filter-btn" data-filter="WARNING" style="background: var(--medium-color);">Warnings</button>
                    <button class="filter-btn" data-filter="PASS" style="background: var(--pass-color); color: white;">Passed</button>
                </div>
            </div>
            {findings_html}
        </section>
        """

    def _generate_finding_card(self, finding: Finding) -> str:
        """Generate a single finding card."""
        severity_lower = finding.severity.name.lower()
        result_lower = finding.result.value.lower()

        # Badge class based on result
        if finding.result == CheckResult.PASS:
            badge_class = "badge-pass"
            header_class = "pass"
        elif finding.result == CheckResult.FAIL:
            badge_class = f"badge-{severity_lower}"
            header_class = severity_lower
        else:
            badge_class = "badge-info"
            header_class = "info"

        # Evidence section
        evidence_html = ""
        if self.include_evidence and finding.evidence:
            evidence_items = "".join([
                f"<div><strong>{e.type}:</strong> {e.description}</div>"
                for e in finding.evidence[:5]  # Limit to 5 items
            ])
            evidence_html = f"""
            <div class="finding-section">
                <h4>Evidence</h4>
                <div class="evidence-box">{evidence_items}</div>
            </div>
            """

        # Remediation section
        remediation_html = ""
        if finding.remediation:
            remediation_html = f"""
            <div class="finding-section">
                <h4>Remediation</h4>
                <div class="remediation-box">{finding.remediation}</div>
            </div>
            """

        # References section
        references_html = ""
        if finding.cwe_ids or finding.cve_ids or finding.references:
            refs = []
            for cwe in finding.cwe_ids:
                refs.append(f'<a href="https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html" target="_blank">{cwe}</a>')
            for cve in finding.cve_ids:
                refs.append(f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a>')
            for ref in finding.references[:3]:
                refs.append(f'<a href="{ref}" target="_blank">{ref[:50]}...</a>' if len(ref) > 50 else f'<a href="{ref}" target="_blank">{ref}</a>')

            if refs:
                references_html = f"""
                <div class="finding-section">
                    <h4>References</h4>
                    <div>{' | '.join(refs)}</div>
                </div>
                """

        return f"""
        <div class="finding-card" data-severity="{severity_lower}" data-result="{finding.result.value}">
            <div class="finding-header {header_class}">
                <div class="finding-title">
                    <span class="finding-id">{finding.check_id}</span>
                    <span>{finding.name}</span>
                </div>
                <span class="severity-badge {badge_class}">{finding.result.value}</span>
            </div>
            <div class="finding-content">
                <p><strong>Category:</strong> {finding.category.value}</p>
                <p><strong>Severity:</strong> {finding.severity.name}</p>

                <div class="finding-section">
                    <h4>Description</h4>
                    <p>{finding.description}</p>
                </div>

                {f'<div class="finding-section"><h4>Details</h4><p>{finding.details}</p></div>' if finding.details else ''}
                {remediation_html}
                {evidence_html}
                {references_html}
            </div>
        </div>
        """

    def _generate_footer(self, data: ReportData) -> str:
        """Generate report footer."""
        return f"""
        <footer class="footer">
            <p>Generated by {data.tool_name} v{data.tool_version}</p>
            <p>Report ID: {data.report_id} | Generated: {data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report is for authorized security testing purposes only.</p>
        </footer>
        """
