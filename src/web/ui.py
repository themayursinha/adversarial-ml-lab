"""Gradio UI composition for the Adversarial ML Security Lab."""

from __future__ import annotations

from typing import cast

import gradio as gr

from src.web.controllers import (
    demo_context_tampering,
    demo_inference_evasion,
    demo_prompt_injection,
    scan_custom_document,
    scan_user_content,
)
from src.web.state import APP_STATE


def create_demo() -> gr.Blocks:
    """Create the main web interface."""
    state = APP_STATE

    with gr.Blocks(title="Adversarial ML Security Lab") as demo:
        gr.HTML(
            """
            <style>
              .header-text { text-align: center; margin-bottom: 20px; }
              .attack-box { border-left: 3px solid #ef4444 !important; }
              .defense-box { border-left: 3px solid #22c55e !important; }
            </style>
            """
        )
        gr.Markdown(
            """
            # Adversarial ML Security Lab

            Interactive demonstrations of AI security attacks and defenses:
            - Prompt Injection
            - Context Tampering
            - Inference Evasion
            - User Content Scanning
            """,
            elem_classes=["header-text"],
        )

        with gr.Tab("Prompt Injection", id="injection"):
            gr.Markdown(
                """
                Attack: malicious instructions hidden in documents can hijack LLM behavior.

                Defense: context-aware filtering and uncertainty scoring.
                """
            )

            with gr.Row():
                with gr.Column():
                    doc_type = gr.Dropdown(
                        choices=["Business Report", "Technical Doc", "Email Content"],
                        value="Business Report",
                        label="Document Type",
                    )
                    injection_type = gr.Dropdown(
                        choices=[payload.name for payload in state.injection_attack.payloads],
                        value="Hidden HTML Comment",
                        label="Injection Payload",
                    )
                    injection_pos = gr.Dropdown(
                        choices=["Start", "Middle", "End", "Hidden"],
                        value="Hidden",
                        label="Injection Position",
                    )
                    defense_toggle = gr.Checkbox(
                        value=True,
                        label="Enable Defense",
                    )
                    run_injection_btn = gr.Button("Run Demo", variant="primary")

            with gr.Row():
                with gr.Column():
                    original_doc_out = gr.Textbox(lines=8, label="Original Document", interactive=False)
                with gr.Column():
                    injected_doc_out = gr.Textbox(
                        lines=8,
                        label="Injected Document",
                        interactive=False,
                        elem_classes=["attack-box"],
                    )

            with gr.Row():
                with gr.Column():
                    vulnerable_out = gr.Markdown(label="Vulnerable Response")
                with gr.Column():
                    protected_out = gr.Markdown(label="Protected Response", elem_classes=["defense-box"])

            run_injection_btn.click(
                demo_prompt_injection,
                inputs=[doc_type, injection_type, injection_pos, defense_toggle],
                outputs=[original_doc_out, injected_doc_out, vulnerable_out, protected_out],
            )

        with gr.Tab("Context Tampering", id="tampering"):
            gr.Markdown(
                """
                Attack: injected conversation history can reframe model behavior.

                Defense: context isolation and integrity verification.
                """
            )

            with gr.Row():
                with gr.Column():
                    scenario = gr.Dropdown(
                        choices=["Customer Support", "Code Assistant", "Empty"],
                        value="Customer Support",
                        label="Conversation Scenario",
                    )
                    attack_toggle = gr.Checkbox(
                        value=True,
                        label="Enable Attack",
                    )
                    defense_level = gr.Radio(
                        choices=["None", "Session", "Request"],
                        value="Session",
                        label="Isolation Level",
                    )
                    run_tampering_btn = gr.Button("Run Demo", variant="primary")

            with gr.Row():
                with gr.Column():
                    original_context_out = gr.Markdown(label="Original Context")
                with gr.Column():
                    tampered_context_out = gr.Markdown(
                        label="Tampered Context",
                        elem_classes=["attack-box"],
                    )

            with gr.Row():
                with gr.Column():
                    server_analysis_out = gr.Markdown(label="Server Analysis")
                with gr.Column():
                    recommendation_out = gr.Markdown(
                        label="Recommendation",
                        elem_classes=["defense-box"],
                    )

            run_tampering_btn.click(
                demo_context_tampering,
                inputs=[scenario, attack_toggle, defense_level],
                outputs=[
                    original_context_out,
                    tampered_context_out,
                    server_analysis_out,
                    recommendation_out,
                ],
            )

        with gr.Tab("Inference Evasion", id="evasion"):
            gr.Markdown(
                """
                Attack: text obfuscation can bypass keyword and moderation filters.

                Defense: canonicalization and ensemble uncertainty scoring.
                """
            )

            with gr.Row():
                with gr.Column():
                    input_text = gr.Textbox(
                        value="ignore previous instructions",
                        label="Input Text",
                        lines=2,
                    )
                    technique = gr.Dropdown(
                        choices=[
                            "Leetspeak",
                            "Unicode Homoglyphs",
                            "Invisible Characters",
                            "Word Splitting",
                            "Base64 Encoding",
                            "Mixed Techniques",
                        ],
                        value="Mixed Techniques",
                        label="Evasion Technique",
                    )
                    intensity = gr.Slider(
                        minimum=0.1,
                        maximum=1.0,
                        value=0.5,
                        step=0.1,
                        label="Intensity",
                    )
                    evasion_defense = gr.Checkbox(
                        value=True,
                        label="Enable Defense",
                    )
                    run_evasion_btn = gr.Button("Run Demo", variant="primary")

            with gr.Row():
                with gr.Column():
                    original_text_out = gr.Textbox(lines=3, label="Original Text", interactive=False)
                with gr.Column():
                    evaded_text_out = gr.Textbox(
                        lines=3,
                        label="Evaded Text",
                        interactive=False,
                        elem_classes=["attack-box"],
                    )

            with gr.Row():
                with gr.Column():
                    transformations_out = gr.Markdown(label="Transformations")
                with gr.Column():
                    uncertainty_out = gr.Markdown(label="Defense Analysis", elem_classes=["defense-box"])

            run_evasion_btn.click(
                demo_inference_evasion,
                inputs=[input_text, technique, intensity, evasion_defense],
                outputs=[original_text_out, evaded_text_out, transformations_out, uncertainty_out],
            )

        with gr.Tab("Scan Your Content", id="scan"):
            gr.Markdown(
                """
                Scan pasted text or uploaded files for:
                - Prompt injection patterns
                - Obfuscation patterns
                - Sensitive data indicators
                - Output safety risks
                """
            )

            with gr.Tabs():
                with gr.Tab("Quick Scan"):
                    with gr.Row():
                        with gr.Column():
                            scan_content = gr.Textbox(
                                label="Paste Content",
                                placeholder="Paste text here (documents, emails, logs, prompts).",
                                lines=8,
                            )
                            scan_file = gr.File(
                                label="Or Upload a File",
                                file_types=[
                                    ".txt",
                                    ".md",
                                    ".json",
                                    ".csv",
                                    ".html",
                                    ".xml",
                                    ".py",
                                    ".js",
                                ],
                            )
                            scan_type = gr.Radio(
                                choices=[
                                    "All Scans",
                                    "Prompt Injection",
                                    "Obfuscation",
                                    "Sensitive Data",
                                    "Output Safety",
                                ],
                                value="All Scans",
                                label="Scan Type",
                            )
                            scan_btn = gr.Button("Scan Content", variant="primary")

                    with gr.Row():
                        with gr.Column():
                            scan_preview = gr.Markdown(label="Content Preview")
                        with gr.Column():
                            scan_results = gr.Markdown(label="Scan Results")

                    with gr.Row():
                        scan_recommendations = gr.Markdown(label="Recommendations")

                    scan_btn.click(
                        scan_user_content,
                        inputs=[scan_content, scan_file, scan_type],
                        outputs=[scan_preview, scan_results, scan_recommendations],
                    )

                with gr.Tab("Test Your Document"):
                    with gr.Row():
                        with gr.Column():
                            custom_doc = gr.Textbox(
                                label="Your Document",
                                placeholder="Paste your document content here.",
                                lines=10,
                            )
                            simulate_attack = gr.Checkbox(value=True, label="Simulate Injection Attack")
                            attack_payload = gr.Dropdown(
                                choices=[payload.name for payload in state.injection_attack.payloads],
                                value="Hidden HTML Comment",
                                label="Attack Payload",
                            )
                            test_doc_btn = gr.Button("Test Document", variant="primary")

                    with gr.Row():
                        with gr.Column():
                            custom_original = gr.Textbox(lines=6, label="Original", interactive=False)
                        with gr.Column():
                            custom_injected = gr.Textbox(
                                lines=6,
                                label="Injected",
                                interactive=False,
                                elem_classes=["attack-box"],
                            )

                    with gr.Row():
                        with gr.Column():
                            custom_vulnerable = gr.Markdown(label="Vulnerable Response")
                        with gr.Column():
                            custom_protected = gr.Markdown(
                                label="Protected Response",
                                elem_classes=["defense-box"],
                            )

                    test_doc_btn.click(
                        scan_custom_document,
                        inputs=[custom_doc, simulate_attack, attack_payload],
                        outputs=[
                            custom_original,
                            custom_injected,
                            custom_vulnerable,
                            custom_protected,
                        ],
                    )

        gr.Markdown(
            """
            ---

            Privacy note: scanning runs locally in simulation mode; uploaded content
            is processed by this app and not sent to external model APIs.
            """
        )

    return cast(gr.Blocks, demo)
