'use strict';

// The table contains a small window of fixed-height rows. Spacer rows retain
// the full scroll range without creating tens of thousands of DOM elements.
// Keep this in sync with the h-11 table cells in scan.html.ep and render().
const rowHeight = 44;

class ResultTable {
  constructor(element, worker) {
    this.element = element;
    this.kind = element.dataset.resultTable;
    this.worker = worker;
    this.viewport = element.querySelector('[data-result-viewport]');
    this.body = element.querySelector('tbody');
    this.search = element.querySelector('[data-result-search]');
    this.status = element.querySelector('[data-result-status]');
    this.count = element.querySelector('[data-result-count]');
    this.column = null;
    this.descending = false;
    this.sequence = 0;

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
    if (reset) this.viewport.scrollTop = 0;
    this.worker.postMessage({type: 'window', kind: this.kind, sequence: ++this.sequence,
      query: this.search.value, column: this.column, descending: this.descending,
      start: Math.max(0, Math.floor(this.viewport.scrollTop / rowHeight) - 8)});
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
    const fragment = document.createDocumentFragment();
    if (result.start) fragment.append(this.spacer(result.start * rowHeight));
    for (const [offset, values] of result.rows.entries()) {
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
    const remaining = result.count - result.start - result.rows.length;
    if (remaining > 0) fragment.append(this.spacer(remaining * rowHeight));
    this.body.replaceChildren(fragment);
    this.element.querySelector('table').setAttribute('aria-rowcount', result.count + 1);
    const format = value => value.toLocaleString();
    this.count.textContent = result.count === result.total ? `${format(result.total)} 件` : `${format(result.count)} / ${format(result.total)} 件`;
    this.viewport.hidden = result.count === 0;
    this.status.hidden = result.count > 0;
    this.status.textContent = result.count === 0 ? '該当する項目はありません。' : '';
  }

  fail() {
    this.status.hidden = false;
    this.status.textContent = '読み込めませんでした。画面を更新するか JSON をダウンロードしてください。';
  }
}

const resultElements = Array.from(document.querySelectorAll('[data-result-table]')).filter(element => element.dataset.source);
if (resultElements.length) {
  if (typeof Worker === 'undefined') {
    for (const element of resultElements) element.querySelector('[data-result-status]').textContent = 'このブラウザーでは一覧を表示できません。JSON をダウンロードしてください。';
  } else {
    const worker = new Worker('/results-worker.js');
    const tables = new Map(resultElements.map(element => [element.dataset.resultTable, new ResultTable(element, worker)]));
    const sources = resultElements.map(element => ({kind: element.dataset.resultTable, url: new URL(element.dataset.source, location.href).href}));
    const cacheStatus = document.querySelector('[data-cache-status]');
    const clearCache = document.querySelector('[data-clear-cache]');
    worker.onmessage = ({data}) => {
      if (data.type.startsWith('cache-')) {
        if (data.type === 'cache-ready') {
          clearCache.hidden = !data.available;
          cacheStatus.hidden = data.saved;
          cacheStatus.textContent = 'このブラウザーに結果を保存できませんでした。再表示時に再取得します。';
        } else {
          clearCache.disabled = false;
          cacheStatus.hidden = false;
          cacheStatus.textContent = data.type === 'cache-cleared'
            ? 'キャッシュを削除しました。次回の表示時に再取得します。'
            : 'キャッシュを削除できませんでした。';
        }
        return;
      }
      const table = tables.get(data.kind);
      if (data.type === 'ready') table.ready();
      if (data.type === 'rows') table.render(data);
      if (data.type === 'failure') table.fail();
    };
    clearCache.addEventListener('click', () => {
      clearCache.disabled = true;
      worker.postMessage({type: 'clear-cache', sources});
    });
    worker.onerror = () => tables.forEach(table => table.fail());
    worker.postMessage({type: 'load', sources});
    window.addEventListener('pagehide', event => {if (!event.persisted) worker.terminate();});
  }
}
