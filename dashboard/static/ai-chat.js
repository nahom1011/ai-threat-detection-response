/**
 * AI Security Analyst Chat Widget
 * Streams responses from Claude with live dashboard context.
 */

let aiChatOpen = false;
let aiIsTyping = false;

// ==================== TOGGLE ====================

document.getElementById('ai-chat-toggle').addEventListener('click', () => {
    aiChatOpen = !aiChatOpen;
    const panel = document.getElementById('ai-chat-panel');
    const badge = document.getElementById('ai-chat-badge');
    if (aiChatOpen) {
        panel.style.display = 'flex';
        badge.style.display = 'none';
        document.getElementById('ai-chat-input').focus();
        setTimeout(() => panel.classList.add('ai-panel-open'), 10);
    } else {
        panel.classList.remove('ai-panel-open');
        setTimeout(() => { panel.style.display = 'none'; }, 300);
    }
});

document.getElementById('ai-chat-close').addEventListener('click', () => {
    aiChatOpen = false;
    const panel = document.getElementById('ai-chat-panel');
    panel.classList.remove('ai-panel-open');
    setTimeout(() => { panel.style.display = 'none'; }, 300);
});

// ==================== SEND MESSAGE ====================

function sendSuggestion(text) {
    document.getElementById('ai-chat-input').value = text;
    sendAiMessage();
}

async function sendAiMessage() {
    if (aiIsTyping) return;

    const input = document.getElementById('ai-chat-input');
    const message = input.value.trim();
    if (!message) return;

    input.value = '';
    input.style.height = 'auto';
    aiIsTyping = true;

    document.getElementById('ai-send-icon').textContent = '⏳';

    // Append user message
    appendMessage('user', message);

    // Append AI typing bubble
    const aiMsgId = 'ai-msg-' + Date.now();
    appendMessage('ai', '', aiMsgId);

    try {
        const response = await fetch('/api/ai-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });

        if (!response.ok) {
            const err = await response.json();
            updateMessage(aiMsgId, '⚠️ ' + (err.error || 'Something went wrong.'));
            return;
        }

        // Stream the response text
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullText = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value, { stream: true });
            fullText += chunk;
            updateMessage(aiMsgId, fullText);
        }

    } catch (err) {
        updateMessage(aiMsgId, '⚠️ Could not reach the AI assistant. Please check your connection.');
        console.error('AI chat error:', err);
    } finally {
        aiIsTyping = false;
        document.getElementById('ai-send-icon').textContent = '➤';
    }
}

// ==================== DOM HELPERS ====================

function appendMessage(role, text, id) {
    const container = document.getElementById('ai-chat-messages');

    const wrapper = document.createElement('div');
    wrapper.className = `ai-chat-msg ai-chat-msg-${role}`;
    if (id) wrapper.id = id;

    if (role === 'ai') {
        wrapper.innerHTML = `
            <span class="ai-msg-avatar">🛡️</span>
            <div class="ai-msg-bubble">${text || '<span class="ai-typing"><span></span><span></span><span></span></span>'}</div>
        `;
    } else {
        wrapper.innerHTML = `
            <div class="ai-msg-bubble ai-msg-bubble-user">${escapeHtml(text)}</div>
            <span class="ai-msg-avatar ai-msg-avatar-user">👤</span>
        `;
    }

    container.appendChild(wrapper);
    container.scrollTop = container.scrollHeight;
}

function updateMessage(id, text) {
    const el = document.getElementById(id);
    if (!el) return;
    const bubble = el.querySelector('.ai-msg-bubble');
    if (bubble) {
        bubble.innerHTML = formatAiText(text);
        el.parentElement.scrollTop = el.parentElement.scrollHeight;
    }
}

function formatAiText(text) {
    // Convert markdown-style bold (**text**) and newlines to HTML
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
}

function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

// ==================== KEYBOARD SHORTCUT ====================

document.getElementById('ai-chat-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendAiMessage();
    }
});

// Auto-resize textarea
document.getElementById('ai-chat-input').addEventListener('input', function () {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
});
