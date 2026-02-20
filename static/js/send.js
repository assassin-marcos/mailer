document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("email-form");
    if (!form) return;

    const terminal = document.getElementById("terminal");
    const terminalOutput = document.getElementById("terminal-output");
    const terminalStatus = document.getElementById("terminal-status");

    const MAX_LINES = 50;

    function terminalLog(message, type) {
        const line = document.createElement("div");
        line.className = "terminal-line terminal-" + (type || "info");

        const time = new Date().toLocaleTimeString("en-IN", { hour12: true, timeZone: 'Asia/Kolkata' });
        line.textContent = `[${time}] ${message}`;

        terminalOutput.appendChild(line);

        // Keep max lines
        while (terminalOutput.children.length > MAX_LINES) {
            terminalOutput.removeChild(terminalOutput.firstChild);
        }

        // Auto-scroll
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        // Show terminal, clear previous output
        terminal.style.display = "block";
        terminalOutput.innerHTML = "";
        terminalStatus.textContent = "Preparing...";

        try {
            // 1. Parse domains from textarea
            const domainsText = form.querySelector('[name="domains"]').value;
            let domains = domainsText
                .split(/[\n,]+/)
                .map(d => d.trim())
                .filter(d => d.length > 0);

            // 2. Parse domain file if uploaded
            const domainFileInput = form.querySelector('[name="domain_file"]');
            if (domainFileInput && domainFileInput.files[0]) {
                const fileText = await domainFileInput.files[0].text();
                const fileDomains = fileText
                    .split(/[\n,]+/)
                    .map(d => d.trim())
                    .filter(d => d.length > 0);
                domains = domains.concat(fileDomains);
            }

            // 3. Parse email file if uploaded
            let directEmails = [];
            const emailFileInput = form.querySelector('[name="email_file"]');
            if (emailFileInput && emailFileInput.files[0]) {
                const fileText = await emailFileInput.files[0].text();
                directEmails = fileText
                    .split(/[\n,]+/)
                    .map(e => e.trim())
                    .filter(e => e.length > 0);
            }

            // 4. Validate
            if (domains.length === 0 && directEmails.length === 0) {
                terminalLog("Error: Provide at least one domain or email file.", "error");
                terminalStatus.textContent = "Error";
                return;
            }

            // 5. Gather selected usernames
            const selectedUsernames = Array.from(
                form.querySelectorAll('input[name="selected_usernames"]:checked')
            ).map(cb => cb.value);

            // 6. Build request body
            const trackingCheckbox = form.querySelector('[name="enable_tracking"]');
            const body = {
                domains: domains,
                selected_cred: form.querySelector('[name="selected_cred"]').value,
                selected_usernames: selectedUsernames,
                custom_usernames: form.querySelector('[name="custom_usernames"]').value,
                direct_emails: directEmails,
                template_id: form.querySelector('[name="template_id"]').value,
                sender_name: form.querySelector('[name="sender_name"]').value,
                enable_tracking: trackingCheckbox ? trackingCheckbox.checked : false
            };

            terminalLog("Initializing send task...", "info");

            // 7. POST to start task
            const startRes = await fetch("/send_emails_start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body)
            });

            const startData = await startRes.json();

            if (startData.error) {
                terminalLog("Error: " + startData.error, "error");
                terminalStatus.textContent = "Error";
                return;
            }

            const taskId = startData.task_id;
            terminalLog("Task started. Connecting to stream...", "info");
            terminalStatus.textContent = "Sending...";

            // 8. Open SSE stream
            const evtSource = new EventSource("/send_emails_stream?task_id=" + taskId);

            evtSource.onmessage = (event) => {
                const data = JSON.parse(event.data);

                switch (data.type) {
                    case "mx_check":
                        if (data.success) {
                            terminalLog(`✓ ${data.message}`, "success");
                        } else {
                            terminalLog(`✗ ${data.message}`, "error");
                        }
                        break;

                    case "start":
                        terminalLog(`Starting: ${data.total} email(s) across ${data.workers} concurrent worker(s)`, "info");
                        break;

                    case "sending":
                        terminalLog(`[${data.domain}] Sending to ${data.to} via ${data.via}...`, "info");
                        break;

                    case "result":
                        if (data.success) {
                            terminalLog(`[${data.domain}] OK: ${data.message}`, "success");
                        } else {
                            terminalLog(`[${data.domain}] FAIL: ${data.message}`, "error");
                        }
                        break;

                    case "complete":
                        terminalLog(`Complete: ${data.sent} sent, ${data.failed} failed out of ${data.total}`, "info");
                        terminalStatus.textContent = `Done: ${data.sent} sent, ${data.failed} failed`;
                        evtSource.close();
                        break;
                }
            };

            evtSource.onerror = () => {
                terminalLog("Connection lost.", "error");
                terminalStatus.textContent = "Disconnected";
                evtSource.close();
            };

        } catch (err) {
            terminalLog("Error: " + err.message, "error");
            terminalStatus.textContent = "Error";
        }
    });
});
