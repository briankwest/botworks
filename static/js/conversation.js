// conversation.js

document.addEventListener("DOMContentLoaded", function() {
    // Extract the id from the URL
    const urlParts = window.location.pathname.split('/');
    const id = urlParts.pop() || urlParts.pop(); // Handles potential trailing slash

    function fetchData(id) {
        fetch(`/conversations/${id}`)
            .then(response => response.json())
            .then(responseData => {
                clearContent(); // Clear existing content
                displayData(responseData.data);
                setupNavigationButtons(responseData.next, responseData.prev);
            })
            .catch(error => console.error('Error fetching JSON:', error));
    }

    function clearContent() {
        const content = document.getElementById('PostPromptDataContent');
        content.innerHTML = ''; // Clear existing content
    }

    function setupNavigationButtons(nextId, prevId) {
        const content = document.getElementById('PostPromptDataContent');

        // Create navigation buttons container
        let navContainer = document.getElementById('navContainer');
        if (!navContainer) {
            navContainer = document.createElement('div');
            navContainer.id = 'navContainer';
            navContainer.className = 'd-flex justify-content-between mb-3'; // Flexbox for alignment
            content.insertAdjacentElement('beforebegin', navContainer); // Insert before content
        }
        navContainer.innerHTML = ''; // Clear previous buttons

        // Create Previous button
        if (prevId) {
            const prevButton = document.createElement('button');
            prevButton.className = 'btn btn-primary'; // AdminLTE button class
            prevButton.innerText = 'Previous';
            prevButton.onclick = () => {
                fetchData(prevId);
                history.pushState(null, '', `/conversation/view/${prevId}`); // Update URL
            };
            navContainer.appendChild(prevButton);
        }

        // Create Next button
        if (nextId) {
            const nextButton = document.createElement('button');
            nextButton.className = 'btn btn-primary ml-auto'; // AdminLTE button class with margin-left auto
            nextButton.innerText = 'Next';
            nextButton.onclick = () => {
                fetchData(nextId);
                history.pushState(null, '', `/conversation/view/${nextId}`); // Update URL
            };
            navContainer.appendChild(nextButton);
        }
    }

    // Initial fetch
    fetchData(id);

    function displayData(data) {
        const content = document.getElementById('PostPromptDataContent');

        // Display Interaction Details
        const interactionDetailsCard = createCard('Interaction Details', createInteractionDetailsTable(data), 'bg-info');
        content.appendChild(interactionDetailsCard);

        // Display Call Log
        const callLogCard = createCard('Call Log', createCallLogTable(data.raw_call_log), 'bg-success');
        content.appendChild(callLogCard);

        // Display Times
        const timesCard = createCard('Times', createTimesTable(data.times), 'bg-warning');
        content.appendChild(timesCard);

        // Display SWML Vars
        const swmlVarsCard = createCard('SWML Vars', createSWMLVarsTable(data.SWMLVars), 'bg-danger');
        content.appendChild(swmlVarsCard);

        // Display SWAIG Log
        const swaigLogCard = createCard('SWAIG Log', createSwaigLogTable(data.swaig_log), 'bg-secondary');
        content.appendChild(swaigLogCard);

        // Display Post Prompt Data
        const postPromptDataCard = createCard('Post Prompt Data', createPostPromptDataTable(data.post_prompt_data), 'bg-primary');
        content.appendChild(postPromptDataCard);
    }

    function createCard(title, contentHtml, headerClass) {
        const card = document.createElement('div');
        card.className = 'card mb-3'; // Add margin-bottom for spacing

        const cardHeader = document.createElement('div');
        cardHeader.className = 'card-header ' + (headerClass || 'bg-info'); // Add background color

        const cardTitle = document.createElement('h5'); // Change to h5 for consistency
        cardTitle.className = 'card-title';
        cardTitle.innerText = title;

        cardHeader.appendChild(cardTitle);

        const cardBody = document.createElement('div');
        cardBody.className = 'card-body';
        cardBody.innerHTML = contentHtml;

        card.appendChild(cardHeader);
        card.appendChild(cardBody);

        return card;
    }

    function createInteractionDetailsTable(data) {
        let table = '<table class="table table-striped table-sm">'; // Added 'table-sm' for smaller padding
        table += `
        <tr>
            <th style="width: 45%;">Key</th>
            <th style="width: 45%;">Value</th>
            <th style="width: 5%;">Copy</th>
        </tr>
        <tr>
            <td>Call ID</td>
            <td>${data.call_id || ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.call_id || ''}')"></i></td>
        </tr>
        <tr>
            <td>Caller ID Name</td>
            <td>${data.caller_id_name || ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.caller_id_name || ''}')"></i></td>
        </tr>
        <tr>
            <td>Caller ID Number</td>
            <td>${data.caller_id_number || ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.caller_id_number || ''}')"></i></td>
        </tr>
        <tr>
            <td>Call Start Date</td>
            <td>${data.call_start_date ? new Date(data.call_start_date / 1000).toISOString().replace('T', ' ').replace('Z', ' UTC') : ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.call_start_date ? new Date(data.call_start_date / 1000).toISOString() : ''}')"></i></td>
        </tr>
        <tr>
            <td>Call End Date</td>
            <td>${data.call_end_date ? new Date(data.call_end_date / 1000).toISOString().replace('T', ' ').replace('Z', ' UTC') : ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.call_end_date ? new Date(data.call_end_date / 1000).toISOString() : ''}')"></i></td>
        </tr>
        <tr>
            <td>AI Start Date</td>
            <td>${data.ai_start_date ? new Date(data.ai_start_date / 1000).toISOString().replace('T', ' ').replace('Z', ' UTC') : ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.ai_start_date ? new Date(data.ai_start_date / 1000).toISOString() : ''}')"></i></td>
        </tr>
        <tr>
            <td>AI End Date</td>
            <td>${data.ai_end_date ? new Date(data.ai_end_date / 1000).toISOString().replace('T', ' ').replace('Z', ' UTC') : ''}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${data.ai_end_date ? new Date(data.ai_end_date / 1000).toISOString() : ''}')"></i></td>
        </tr>`;
        const additionalFields = [
            { key: 'Total Input Tokens', value: data.total_input_tokens },
            { key: 'Total Output Tokens', value: data.total_output_tokens },
            { key: 'Total ASR Cost Factor', value: data.total_asr_cost_factor },
            { key: 'Total ASR Minutes', value: data.total_asr_minutes },
            { key: 'Total Minutes', value: data.total_minutes },
            { key: 'Total TTS Chars Per Minute', value: data.total_tts_chars_per_min },
            { key: 'Total Wire Input Tokens Per Minute', value: data.total_wire_input_tokens_per_minute },
            { key: 'Total Wire Output Tokens Per Minute', value: data.total_wire_output_tokens_per_minute },
        ];

        additionalFields.forEach(field => {
            if (field.value !== undefined) {
                table += `
        <tr>
            <td>${field.key}</td>
            <td>${field.value}</td>
            <td class="copy-btn"><i class="fas fa-copy" onclick="copyToClipboard('${field.value}')"></i></td>
        </tr>`;
            }
        });
        

        table += '</table>';
        return table;
    }

    function createCallLogTable(callLog) {
        let table = '<div style="overflow-x: auto;"><table class="table table-striped table-sm" style="table-layout: fixed; width: 100%;">'; // Added 'table-sm' for smaller padding and fixed layout
        table += `
            <tr>
                <th style="width: 10%;">Role</th>
                <th style="width: 65%;">Content</th>
                <th style="width: 5%;">Latency</th>
                <th style="width: 5%;">Audio Latency</th>
                <th style="width: 5%;">Utterance Latency</th>
            </tr>
        `;
        callLog.forEach(log => {
            // Skip logs with "tool_calls"
            if (log.hasOwnProperty('tool_calls')) {
                return;
            }
            const roleColors = {
                'user': 'bg-primary text-white',
                'assistant': 'bg-success text-white',
                'system': 'bg-warning text-dark',
                'other': 'bg-secondary text-white',
                'system-log': 'bg-warning text-dark',
                'tool': 'bg-info text-dark',
                'other': 'bg-secondary text-dark',
            };

            const roleClass = roleColors[log.role] || 'bg-light text-dark';
            
            table += `
                <tr class="${roleClass}">
                    <td class="role">${log.role}</td>
                    <td style="word-wrap: break-word;">${log.content.replace(/\n/g, '<br/>')}</td>
                    <td>${log.latency ? log.latency + ' ms' : 'N/A'}</td>
                    <td>${log.audio_latency ? log.audio_latency + ' ms' : 'N/A'}</td>
                    <td>${log.utterance_latency ? log.utterance_latency + ' ms' : 'N/A'}</td>
                </tr>
            `;
        });
        table += '</table></div>';
        return table;
    }

    function createTimesTable(times) {
        let table = '<table class="table table-striped table-sm">'; 
        table += `
            <tr>
                <th>Token Time</th>
                <th>Tokens</th>
                <th>TPS</th>
                <th>Avg TPS</th>
                <th>Response Word Count</th>
                <th>Response</th>
                <th>Answer Time</th>
            </tr>
        `;
        times.forEach(time => {
            table += `
                <tr>
                    <td>${time.token_time}</td>
                    <td>${time.tokens}</td>
                    <td>${time.tps}</td>
                    <td>${time.avg_tps}</td>
                    <td>${time.response_word_count}</td>
                    <td>${time.response}</td>
                    <td>${time.answer_time}</td>
                </tr>
            `;
        });
        table += '</table>';
        return table;
    }

    function createSWMLVarsTable(swmlVars) {
        let table = '<table class="table table-striped table-sm">'; // Added 'table-sm' for smaller padding
        table += `
            <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Copy</th>
            </tr>
        `;
        for (const [key, value] of Object.entries(swmlVars)) {
            table += `
                <tr>
                    <td>${key}</td>
                    <td>
                        ${value}
                        ${key === 'record_call_url' ? `<audio controls src="${value}" style="margin-left: 10px;" style="height: 10px;"></audio>` : ''}
                    </td>
                    <td class="copy-btn"><i class="fas fa-copy" data-copy="${value}" onclick="copyToClipboard('${value}')"></i></td>
                </tr>
            `;
        }
        table += '</table>';
        return table;
    }

    function createSwaigLogTable(swaigLog) {
        let table = '<div class="table-responsive"><table class="table table-striped table-sm">'; // Added 'table-sm' for smaller padding
        table += `
            <tr>
                <th>URL</th>
                <th>Active Count</th>
                <th>Command Name</th>
                <th>Command Arg</th>
                <th>Post Data</th>
                <th>Post Response</th>
                <th>Epoch Time</th>
            </tr>
        `;
        swaigLog.forEach(log => {
            // Determine if the post response is delayed and adjust cell style accordingly
            const isDelayed = log.delayed_post_response ? true : false;
            const postResponse = isDelayed ? log.delayed_post_response : log.post_response;
            const postResponseClass = isDelayed ? 'delayed-response' : '';

            table += `
            <tr>
                <td>
                    <input type="text" readonly value="${log.url}" style="width: 200px;">
                    <i class="fas fa-copy copy-btn" data-copy="${log.url}" onclick="copyToClipboard(this.getAttribute('data-copy'))"></i>
                </td>
                <td>${log.active_count}</td>
                <td>${log.command_name}</td>
                <td>
                    <textarea readonly style="width: 100%; max-width: 200px;">${JSON.stringify(JSON.parse(log.command_arg), null, 2)}</textarea>
                    <i class="fas fa-copy copy-btn" data-copy='${JSON.stringify(JSON.parse(log.command_arg), null, 2)}' onclick="copyToClipboard(this.getAttribute('data-copy'))"></i>
                </td>
                <td>
                    <textarea readonly style="width: 100%; max-width: 300px;">${JSON.stringify(log.post_data, null, 2)}</textarea>
                    <i class="fas fa-copy copy-btn" data-copy="${JSON.stringify(log.post_data, null, 2)}" onclick="copyToClipboard(this.getAttribute('data-copy'))"></i>
                </td>
                <td class="${postResponseClass}">
                    <textarea readonly style="width: 100%; max-width: 300px;">${JSON.stringify(postResponse, null, 2)}</textarea>
                    <i class="fas fa-copy copy-btn" data-copy="${JSON.stringify(postResponse, null, 2)}" onclick="copyToClipboard(this.getAttribute('data-copy'))"></i>
                </td>
                <td class="nowrap">${new Date(log.epoch_time * 1000).toLocaleString()}
                </td>
            </tr>
        `;
        });
        table += '</table></div>';
        return table;
    }

    function createPostPromptDataTable(postPromptData) {
        let table = '<table class="table table-striped table-sm">'; // Added 'table-sm' for smaller padding

        // Include the raw or substituted data
        if (postPromptData.raw) {
            table += `
            <tr>
                <td><strong>Raw Data:</strong></td>
                <td><pre>${postPromptData.raw}</pre></td>
                <td><i class="fas fa-copy copy-btn" onclick="copyToClipboard(\`${postPromptData.raw}\`)"></i></td>
            </tr>
        `;
        }

        if (postPromptData.substituted) {
            table += `
            <tr>
                <td><strong>Substituted Data:</strong></td>
                <td><pre>${postPromptData.substituted}</pre></td>
                <td><i class="fas fa-copy copy-btn" onclick="copyToClipboard(\`${postPromptData.substituted}\`)"></i></td>
            </tr>
        `;
        }

        // Include parsed data if it exists
        if (postPromptData.parsed && postPromptData.parsed.length > 0) {
            postPromptData.parsed.forEach((parsedItem, index) => {
                table += `
                <tr>
                    <td><strong>Parsed Item ${index + 1}:</strong></td>
                    <td><pre>${JSON.stringify(parsedItem, null, 2)}</pre></td>
                    <td><i class="fas fa-copy copy-btn" onclick="copyToClipboard(\`${JSON.stringify(parsedItem, null, 2)}\`)"></i></td>
                </tr>
            `;
            });
        }

        table += '</table>';
        return table;
    }

    window.copyToClipboard = function(value) {
        const tempInput = document.createElement('textarea');
        tempInput.style.position = 'absolute';
        tempInput.style.left = '-9999px';
        tempInput.value = value;
        document.body.appendChild(tempInput);
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
        const Toast = Swal.mixin({
            toast: true,
            position: 'top-end',
            showConfirmButton: false,
            timer: 1500,
            timerProgressBar: true,
            didOpen: (toast) => {
                toast.addEventListener('mouseenter', Swal.stopTimer)
                toast.addEventListener('mouseleave', Swal.resumeTimer)
            }
        });

        Toast.fire({
            icon: 'success',
            title: 'Copied to clipboard'
        });
    }
});