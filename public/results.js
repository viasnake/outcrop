'use strict';

// The table contains a small window of fixed-height rows. Spacer rows retain
// the full scroll range without creating tens of thousands of DOM elements.
// Keep this in sync with the h-11 table cells in scan.html.ep and render().
const rowHeight = 44;
// Match the API window size so each page contains at most 60 results.
const pageSize = 60;

class ResultTable {
  constructor(element, worker) {
    this.element = element;
    this.kind = element.dataset.resultTable;
    this.worker = worker;
    this.viewport = element.querySelector('[data-result-viewport]');
    this.body = element.querySelector('tbody');
    this.search = element.querySelector('[data-result-search]');
    this.search.maxLength = 500;
    this.status = element.querySelector('[data-result-status]');
    this.progress = element.querySelector('[data-result-progress]');
    this.count = element.querySelector('[data-result-count]');
    this.column = null;
    this.descending = false;
    this.sequence = 0;
    this.pageStart = 0;
    this.pager = element.querySelector('[data-result-pager]');
    this.pager.querySelectorAll('[data-page-step]').forEach(button => {
      button.addEventListener('click', () => {
        this.pageStart += Number(button.dataset.pageStep) * pageSize;
        this.viewport.scrollTop = 0;
        this.request();
      });
    });

    let debounce;
    this.search.addEventListener('input', () => {
      // Invalidate any in-flight result as soon as the query changes.
      this.sequence++;
      clearTimeout(debounce);
      debounce = setTimeout(() => this.request(true), 150);
    });
    element.querySelectorAll('[data-sort]').forEach(button => {
      button.addEventListener('click', () => {
        const column = Number(button.dataset.sort);
        this.descending = this.column === column ? !this.descending : false;
        this.column = column;
        for (const header of element.querySelectorAll('th')) {
          const active = Number(header.querySelector('button').dataset.sort) === column;
          header.setAttribute('aria-sort', active ? (this.descending ? 'descending' : 'ascending') : 'none');
          header.querySelector('[data-sort-indicator]').textContent = active ? (this.descending ? ' ↓' : ' ↑') : ' ↕';
        }
        this.request(true);
      });
    });
    let frame;
    this.viewport.addEventListener('scroll', () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = null;
        this.request();
      });
    }, {passive: true});
  }

  ready() {
    this.loaded = true;
    this.search.disabled = false;
    this.element.querySelectorAll('[data-sort]').forEach(button => {button.disabled = false;});
    this.request(true);
  }

  request(reset = false) {
    if (!this.loaded) return;
    this.pager.querySelectorAll('[data-page-step]').forEach(button => {button.disabled = true;});
    if (reset) {
      this.pageStart = 0;
      this.viewport.scrollTop = 0;
    }
    this.worker.postMessage({type: 'window', kind: this.kind, sequence: ++this.sequence,
      query: this.search.value, column: this.column, descending: this.descending,
      start: this.pageStart + Math.max(0, Math.floor(this.viewport.scrollTop / rowHeight) - 8)});
  }

  spacer(height) {
    const row = document.createElement('tr');
    row.dataset.spacer = '';
    row.setAttribute('aria-hidden', 'true');
    const cell = row.insertCell();
    cell.className = 'border-0 p-0';
    cell.colSpan = 5;
    cell.style.height = `${height}px`;
    return row;
  }

  render(result) {
    if (result.sequence !== this.sequence) return;
    if (this.progress) this.progress.hidden = true;
    const fragment = document.createDocumentFragment();
    const localStart = result.start - this.pageStart;
    const pageCount = Math.min(pageSize, result.count - this.pageStart);
    const rows = result.rows.slice(0, pageCount - localStart);
    if (localStart) fragment.append(this.spacer(localStart * rowHeight));
    for (const [offset, values] of rows.entries()) {
      const row = document.createElement('tr');
      row.setAttribute('aria-rowindex', result.start + offset + 2);
      for (const value of values) {
        const cell = row.insertCell();
        cell.className = 'h-11 truncate border-b border-slate-200 px-3 align-middle';
        cell.textContent = value;
        cell.title = value;
      }
      fragment.append(row);
    }
    const remaining = pageCount - localStart - rows.length;
    if (remaining > 0) fragment.append(this.spacer(remaining * rowHeight));
    this.body.replaceChildren(fragment);
    this.element.querySelector('table').setAttribute('aria-rowcount', result.count + 1);
    const format = value => value.toLocaleString();
    this.pager.hidden = result.count <= pageSize;
    this.pager.querySelector('[data-page-range]').textContent = `${format(this.pageStart + 1)}–${format(this.pageStart + pageCount)} / ${format(result.count)} 件`;
    this.pager.querySelector('[data-page-step="-1"]').disabled = this.pageStart === 0;
    this.pager.querySelector('[data-page-step="1"]').disabled = this.pageStart + pageSize >= result.count;
    this.count.textContent = result.count === result.total ? `${format(result.total)} 件` : `${format(result.count)} / ${format(result.total)} 件`;
    this.viewport.hidden = result.count === 0;
    this.status.hidden = result.count > 0;
    this.status.textContent = result.count === 0 ? '該当する項目はありません。' : '';
  }

  fail(message) {
    if (this.progress) this.progress.hidden = true;
    this.status.hidden = false;
    this.status.textContent = message || '読み込めませんでした。画面を更新するか JSON をダウンロードしてください。';
  }
}

const buildForms = Array.from(document.querySelectorAll('[data-result-build]'));
const buildKinds = new Set(buildForms.map(form => form.dataset.resultBuild));
const resultElements = Array.from(document.querySelectorAll('[data-result-table]')).filter(element => element.dataset.source || buildKinds.has(element.dataset.resultTable));
if (resultElements.length) {
  if (typeof Worker === 'undefined') {
    for (const element of resultElements) element.querySelector('[data-result-status]').textContent = 'このブラウザーでは一覧を表示できません。JSON をダウンロードしてください。';
  } else {
    const worker = new Worker('/results-worker.js');
    const tables = new Map(resultElements.map(element => [element.dataset.resultTable, new ResultTable(element, worker)]));
    const sources = resultElements.filter(element => element.dataset.source).map(element => ({kind: element.dataset.resultTable, url: new URL(element.dataset.source, location.href).href}));
    const cacheStatus = document.querySelector('[data-cache-status]');
    const clearCache = document.querySelector('[data-clear-cache]');
    const cacheStates = new Map();
    let persistenceRequested = false;
    const resultNames = new Map([['packages', 'パッケージ'], ['matches', '脆弱性']]);
    worker.onmessage = ({data}) => {
      if (data.type.startsWith('cache-')) {
        if (data.type === 'cache-ready') {
          if (data.saved && !persistenceRequested) {
            persistenceRequested = true;
            navigator.storage?.persist?.().catch(() => {});
          }
          cacheStates.set(data.kind, data);
          clearCache.hidden = !Array.from(cacheStates.values()).some(state => state.available);
          // Clearing must wait until neither kind can write back a pending load.
          clearCache.disabled = cacheStates.size < sources.length;
          const failed = sources.filter(source => cacheStates.get(source.kind)?.saved === false);
          cacheStatus.hidden = failed.length === 0;
          cacheStatus.textContent = failed.length
            ? `${failed.map(source => resultNames.get(source.kind)).join('・')}の一覧をこのブラウザーに保存できませんでした。`
            : '';
        } else {
          clearCache.disabled = false;
          cacheStatus.hidden = false;
          cacheStatus.textContent = data.type === 'cache-cleared'
            ? 'キャッシュを削除しました。'
            : 'キャッシュを削除できませんでした。';
        }
        return;
      }
      const table = tables.get(data.kind);
      if (data.type === 'ready') table.ready();
      if (data.type === 'rows') table.render(data);
      if (data.type === 'failure' && data.sequence === table.sequence) table.fail(data.message);
    };
    clearCache.addEventListener('click', () => {
      clearCache.disabled = true;
      worker.postMessage({type: 'clear-cache', sources});
    });
    worker.onerror = () => tables.forEach(table => table.fail());
    document.addEventListener('outcrop:result-ready', ({detail}) => {
      const table = tables.get(detail.kind);
      const source = {kind: detail.kind, url: new URL(detail.url, location.href).href};
      const index = sources.findIndex(item => item.kind === detail.kind);
      if (index < 0) sources.push(source);
      else sources[index] = source;
      cacheStates.delete(detail.kind);
      clearCache.disabled = true;
      table.loaded = false;
      table.sequence++;
      table.status.textContent = '読み込み中…';
      table.status.hidden = false;
      if (table.progress) table.progress.hidden = false;
      worker.postMessage({type: 'load', sources: [source]});
    });
    worker.postMessage({type: 'load', sources});
    window.addEventListener('pagehide', event => {if (!event.persisted) worker.terminate();});
  }
}

// Build actions update only their own table; unsaved notes and tag drafts stay.
for (const form of buildForms) {
  const button = form.querySelector('button');
  const message = form.querySelector('[data-build-message]');
  const progress = form.querySelector('[data-build-progress]');
  const section = document.querySelector(`[data-result-table="${form.dataset.resultBuild}"]`);
  let busy = false;
  const json = async (url, options) => {
    const response = await fetch(url, options);
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    return result;
  };
  const build = async statusUrl => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    progress.hidden = false;
    message.textContent = '作成中…';
    try {
      if (!statusUrl) {
        const result = await json(form.action, {method: 'POST', headers: {Accept: 'application/json'}, body: new URLSearchParams(new FormData(form))});
        statusUrl = result.status_url;
      }
      while (true) {
        const result = await json(statusUrl);
        if (result.state === 'ready') {
          section.dataset.source = result.url;
          button.textContent = `${section.dataset.resultTable === 'packages' ? 'パッケージ' : '脆弱性'}一覧を再作成`;
          message.textContent = '';
          document.dispatchEvent(new CustomEvent('outcrop:result-ready', {detail: {kind: section.dataset.resultTable, url: result.url}}));
          break;
        }
        if (result.state !== 'running') throw new Error('作成に失敗しました。元JSONとサーバーの空き容量を確認して再実行してください。');
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (error) {
      message.textContent = error.message || '作成に失敗しました。再実行してください。';
    } finally {
      busy = false;
      button.disabled = false;
      progress.hidden = true;
    }
  };
  form.addEventListener('submit', event => {event.preventDefault(); build();});
  if (form.dataset.buildStatus) build(form.dataset.buildStatus);
}
