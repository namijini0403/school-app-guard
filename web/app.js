const token = location.hash.slice(1);
history.replaceState(null, '', '/');
const labels = { BLOCKED: '학교 웹 공개 불가', REMEDIATE: '수정 후 재검사', REVIEW_REQUIRED: '담당자 확인 필요' };
let latest;
const element = (tag, text, cls) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (cls) node.className = cls; return node; };
async function api(path, body) {
  const response = await fetch(path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  if (!response.ok) throw new Error('접근키가 만료되었거나 입력을 처리하지 못했습니다. 터미널에서 도구를 다시 실행하세요.');
  return response.json();
}
function render(container, report) {
  container.replaceChildren(element('p', labels[report.status] || '담당자 확인 필요', `status ${report.status}`));
  if (report.summary) container.append(element('p', typeof report.summary === 'string' ? report.summary : JSON.stringify(report.summary)));
  if (report.coverage) container.append(element('p', `검사 범위: ${JSON.stringify(report.coverage)}`, 'muted'));
  for (const finding of report.findings || []) {
    const card = element('article', null, 'finding');
    card.append(element('h3', finding.title), element('p', finding.reason));
    card.append(element('p', `수정 방향: ${Array.isArray(finding.remediation) ? finding.remediation.join(' ') : finding.remediation}`));
    if (finding.fileId) {
      card.append(element('small', `${finding.fileId} · ${finding.line || '?'}행 · ${finding.confidence || '위험 신호'}`));
      const reveal = element('button', '이 컴퓨터에서 파일 위치 확인 · 공유 금지'); reveal.type = 'button';
      reveal.addEventListener('click', async () => {
        try { const { relativePath } = await api(`/api/location?id=${encodeURIComponent(finding.fileId)}`); reveal.replaceWith(element('p', relativePath, 'muted')); }
        catch { reveal.textContent = '위치를 확인할 수 없습니다'; }
      });
      card.append(reveal);
    }
    container.append(card);
  }
  for (const limit of report.limitations || []) container.append(element('p', limit, 'muted'));
}
document.querySelector('#questions').addEventListener('submit', async event => {
  event.preventDefault();
  const target = document.querySelector('#report');
  document.querySelector('#results').hidden = false;
  document.querySelector('#download').disabled = true;
  try { latest = await api('/api/assess', Object.fromEntries(new FormData(event.target))); render(target, latest); document.querySelector('#download').disabled = false; }
  catch (error) { latest = null; target.textContent = error.message; }
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
});
document.querySelector('#download').addEventListener('click', () => {
  if (!latest) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(latest, null, 2)], { type: 'application/json' }));
  const link = element('a'); link.href = url; link.download = 'school-app-review.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
api('/api/review').then(({ scan, questionnaire }) => {
  render(document.querySelector('#scan'), scan);
  for (const question of questionnaire) {
    const field = element('div', null, 'field');
    const label = element('label', question.label); label.htmlFor = question.id;
    const select = element('select'); select.id = question.id; select.name = question.id;
    const empty = element('option', '선택하세요 · 확인 필요'); empty.value = ''; empty.disabled = true; empty.selected = true; select.append(empty);
    for (const option of question.options) { const node = element('option', option.label); node.value = option.value; select.append(node); }
    field.append(label, element('p', question.help, 'muted'), select); document.querySelector('#fields').append(field);
  }
}).catch(error => { document.querySelector('#scan').textContent = error.message; document.querySelector('#questions button').disabled = true; });
