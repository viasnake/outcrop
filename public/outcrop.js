'use strict';

const editableTagClasses = 'inline-flex max-w-full items-center rounded-full border border-slate-200 bg-slate-100 px-2.5 py-0.5 text-xs text-slate-700 wrap-anywhere gap-1.5 pr-1';
const removeTagClasses = 'size-7 shrink-0 cursor-pointer rounded-full text-lg leading-none text-slate-500 hover:bg-slate-200 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50';

// Clone confirmation applies only to detached disks, never to the live host.
function updateCloneConfirmation(form) {
  const selected = form.querySelector('input[name="target"]:checked');
  const isClone = selected?.dataset.targetKind === 'clone';
  const confirmation = form.querySelector('[data-clone-confirmation]');
  if (!confirmation) return;

  confirmation.hidden = !isClone;
  const checkbox = confirmation.querySelector('input');
  checkbox.disabled = !isClone;
  checkbox.required = isClone;
}

// Collect tags as separate values. Enter adds a chip without submitting the
// scan form; IME confirmation remains available for Japanese input.
for (const editor of document.querySelectorAll('[data-tag-input]')) {
  const input = editor.querySelector('[name="new_tag"]');
  const container = editor.querySelector('[data-initial-tags]');
  const status = editor.querySelector('[data-tag-input-status]');
  const form = editor.closest('form');

  function addTag() {
    const value = input.value.trim();
    if (!value) return true;
    const existing = Array.from(container.querySelectorAll('input')).map(field => field.value);
    if (existing.includes(value)) {input.value = ''; return true;}
    if (existing.length >= 20 || value.length > 120) {
      status.textContent = 'タグは20個まで、各120文字以内で入力してください。';
      return false;
    }
    const chip = document.createElement('span');
    chip.className = editableTagClasses;
    const text = document.createElement('span');
    text.className = 'min-w-0 wrap-anywhere';
    text.textContent = value;
    const field = document.createElement('input');
    field.type = 'hidden';
    field.name = 'tags';
    field.value = value;
    const remove = document.createElement('button');
    remove.className = removeTagClasses;
    remove.type = 'button';
    remove.textContent = '×';
    remove.setAttribute('aria-label', `${value} を削除`);
    remove.addEventListener('click', () => chip.remove());
    chip.append(text, field, remove);
    container.append(chip);
    input.value = '';
    status.textContent = '';
    return true;
  }

  editor.querySelector('[data-add-tag]').addEventListener('click', () => {addTag(); input.focus();});
  input.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.isComposing) return;
    event.preventDefault();
    addTag();
  });
  form.addEventListener('submit', event => {
    if (!addTag()) event.preventDefault();
  });
}

// Refresh only disk controls; drafts and the submission ID stay in place.
for (const form of document.querySelectorAll('[data-scan-form]')) {
  const panel = form.querySelector('[data-inventory-panel]');
  const inventoryStatus = document.querySelector('[data-inventory-status]');
  const submit = form.querySelector('button[type="submit"]');
  let submitting = false;
  let refreshing = false;

  function updateControls() {
    updateCloneConfirmation(form);
    const selected = form.querySelector('input[name="target"]:checked:not(:disabled)');
    submit.disabled = submitting || !selected;
  }

  async function refreshInventory() {
    if (refreshing || submitting) return;
    refreshing = true;
    try {
      const response = await fetch('/inventory', {cache: 'no-store', signal: AbortSignal.timeout(15000)});
      if (!response.ok) throw new Error('ディスク一覧を更新できません。再試行します。');
      const html = await response.text();
      // Selection may change while the request is in flight.
      const selected = form.querySelector('input[name="target"]:checked')?.value;
      const fragment = document.createElement('template');
      fragment.innerHTML = html;
      panel.replaceChildren(fragment.content);
      for (const input of panel.querySelectorAll('input[name="target"]')) {
        input.checked = input.value === selected && !input.disabled;
      }
      inventoryStatus.textContent = '';
    } catch (error) {
      inventoryStatus.textContent = 'ディスク一覧を更新できません。再試行します。';
      // An old selection must not look current after a failed refresh.
      panel.querySelectorAll('input[name="target"]').forEach(input => {input.disabled = true;});
    } finally {
      refreshing = false;
      updateControls();
    }
  }

  form.addEventListener('change', updateControls);
  form.addEventListener('submit', async event => {
    if (event.defaultPrevented) return;
    event.preventDefault();
    if (submitting) return;
    const body = new URLSearchParams(new FormData(form));
    const status = form.querySelector('[data-scan-status]');
    submitting = true;
    updateControls();
    submit.textContent = '送信中…';
    try {
      const response = await fetch(form.action, {
        method: 'POST', body, headers: {Accept: 'application/json'},
        signal: AbortSignal.timeout(15000)
      });
      if (!response.ok) throw new Error(await response.text());
      const result = await response.json();
      form.elements.scan_id.value = result.next_id;
      const link = document.createElement('a');
      link.href = result.url;
      link.className = 'underline';
      link.textContent = '進捗を確認';
      status.replaceChildren('スキャンを受け付けました。続けて別のディスクを追加できます。 ', link);
    } catch (error) {
      status.textContent = error.message;
    } finally {
      submitting = false;
      submit.textContent = 'スキャン開始';
      updateControls();
      refreshInventory();
    }
  });
  updateControls();
  setInterval(refreshInventory, 5000);
}

// Back/forward navigation can restore a form with its submitting state intact.
window.addEventListener('pageshow', () => {
  for (const form of document.querySelectorAll('[data-submit-once]')) {
    updateCloneConfirmation(form);
    const button = form.querySelector('button[type="submit"]');
    if (button.textContent === '送信中…') {
      button.disabled = false;
      button.textContent = 'スキャン開始';
    }
  }
});

// Tag operations send only additions or one removal. Existing tags are never
// copied into an editable field, so edits in another tab are preserved.
for (const editor of document.querySelectorAll('[data-tag-editor]')) {
  const status = editor.querySelector('[data-tag-status]');
  const token = editor.querySelector('[name="csrf_token"]').value;
  const container = editor.querySelector('[data-scan-tags]');

  function tagElement(tag) {
    const chip = document.createElement('span');
    chip.className = editableTagClasses;
    const link = document.createElement('a');
    link.href = `/history?${new URLSearchParams({tag})}`;
    link.className = 'min-w-0 wrap-anywhere hover:underline';
    link.textContent = tag;
    const form = document.createElement('form');
    form.className = 'flex shrink-0';
    form.method = 'post';
    form.action = editor.dataset.action;
    form.dataset.tagOperation = '';
    for (const [name, value] of Object.entries({csrf_token: token, operation: 'remove', tag})) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.append(input);
    }
    const button = document.createElement('button');
    button.className = removeTagClasses;
    button.type = 'submit';
    button.textContent = '×';
    button.setAttribute('aria-label', `${tag} を削除`);
    form.append(button);
    chip.append(link, form);
    return chip;
  }

  editor.addEventListener('submit', async event => {
    const form = event.target;
    if (!form.matches('[data-tag-operation]')) return;
    event.preventDefault();
    const body = new URLSearchParams(new FormData(form));
    editor.querySelectorAll('button').forEach(button => {button.disabled = true;});
    status.textContent = '保存中…';
    try {
      const response = await fetch(form.action, {
        method: 'POST', body, headers: {Accept: 'application/json'}
      });
      if (!response.ok) throw new Error(response.status === 400 ? await response.text() : '保存できませんでした。');
      const {tags} = await response.json();
      container.replaceChildren(...tags.map(tagElement));
      if (body.get('operation') === 'add') form.elements.tag.value = '';
      status.textContent = body.get('operation') === 'add' ? '追加しました' : '削除しました';
    } catch (error) {
      status.textContent = error.message;
    } finally {
      editor.querySelectorAll('button').forEach(button => {button.disabled = false;});
    }
  });
}

// Notes are annotations: save without reloading cached result tables.
for (const form of document.querySelectorAll('[data-note-editor]')) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = form.querySelector('button');
    const status = form.querySelector('[data-note-status]');
    button.disabled = true;
    status.textContent = '保存中…';
    try {
      const response = await fetch(form.action, {
        method: 'POST', body: new URLSearchParams(new FormData(form)),
        headers: {Accept: 'application/json'}
      });
      if (!response.ok) throw new Error(response.status === 400 ? await response.text() : '保存できませんでした。');
      status.textContent = '保存しました';
    } catch (error) {
      status.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
}
