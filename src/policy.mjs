const yesNoUnknown = [
  { value: 'yes', label: '예' }, { value: 'no', label: '아니요' }, { value: 'unknown', label: '모름 / 확인 필요' },
];
export const questionnaire = [
  ['realStudentData', '실제 학생의 정보를 입력하거나 저장하나요?', '이름뿐 아니라 학번, 목소리, 사진, 성적, 행동 기록도 포함합니다.'],
  ['sensitiveNarratives', '실제 상담·건강·가정사·학교폭력 등의 원문을 다루나요?', '이름을 지워도 사건, 날짜, 가족관계 등으로 학생을 다시 알아볼 수 있습니다.'],
  ['aiProcessing', '외부 또는 내부 AI가 이 정보를 분석하나요?', '챗봇, 요약, 임베딩, 검색 증강, 모델 학습을 모두 포함합니다.'],
  ['publicAccess', '로그인하지 않은 사람이나 다른 학생이 학생 정보에 접근할 수 있나요?', '공유 링크, 다운로드, 저장소, 공개 버킷, 브라우저 번들, 검색 인덱스도 확인합니다.'],
  ['dataMinimized', '목적에 꼭 필요한 정보만 수집하고 직접·간접 식별자를 줄였나요?', '이름 치환이나 해시만으로 익명정보가 되지는 않습니다. 소수 집단과 자유 서술도 검토합니다.'],
  ['accessControlled', '서버에서 사용자별·역할별 접근 권한을 검증하나요?', '화면에서 버튼을 숨기는 것만으로는 부족합니다. 다른 학생 ID로 조회하는 테스트가 필요합니다.'],
  ['logsRedacted', '로그·오류 추적·분석 도구·백업에 원문이 남지 않는지 확인했나요?', '수집 전 차단을 우선하고 보관 기간과 삭제 절차를 검증합니다.'],
  ['retentionDefined', '보관 기간, 삭제 책임자와 백업 삭제 방법이 정해져 있나요?', '목적이 끝난 후 복구 가능한 사본까지 처리해야 합니다.'],
  ['externalTransfer', '학생 정보가 학교 밖 서비스로 전송되나요?', 'AI, 분석 SDK, 오류 수집, 클라우드 저장소와 위탁 서비스를 포함합니다.'],
  ['institutionReview', '학교의 개인정보·보안 담당자가 처리 근거와 운영 절차를 검토했나요?', '이 도구의 결과는 법률 판정이나 학교의 공개 승인서를 대신하지 않습니다.'],
].map(([id, label, help]) => ({ id, label, help, options: yesNoUnknown.map(x => ({ ...x })) }));

const finding = (id, severity, title, reason, remediation) => ({ id, severity, title, reason, remediation, confidence: 'self_reported' });
export function evaluatePolicy(input = {}) {
  const validObject = input !== null && typeof input === 'object' && !Array.isArray(input);
  const answers = validObject ? input : {};
  const value = key => Object.hasOwn(answers, key) && ['yes', 'no', 'unknown'].includes(answers[key]) ? answers[key] : 'unknown';
  const missingAnswers = questionnaire.filter(q => value(q.id) === 'unknown').map(q => q.id);
  const findings = [];
  if (!validObject || Object.keys(answers).some(k => !questionnaire.some(q => q.id === k))) {
    findings.push(finding('QUESTIONNAIRE_INVALID', 'review', '설문 형식을 확인해 주세요', '알 수 없는 항목이나 잘못된 응답은 안전하다는 근거가 될 수 없습니다.', '제공된 설문의 모든 항목에 예·아니요·모름으로 다시 응답하세요.'));
  }
  const student = value('realStudentData') === 'yes' || value('sensitiveNarratives') === 'yes';
  if (value('sensitiveNarratives') === 'yes' && value('aiProcessing') === 'yes') {
    findings.push(finding('SENSITIVE_AI_ARCHITECTURE', 'blocker', '현재 구조로는 학교 웹에 공개할 수 없습니다', '실제 학생의 상담·건강·가정사 등의 원문을 AI가 분석하는 구조입니다. 이름을 바꾸어도 사건과 관계를 조합하면 재식별될 수 있고, 입력·응답·임베딩·로그·백업에 민감한 내용이 남을 수 있습니다. 내부 AI도 접근 권한과 보관 위험을 없애지는 못합니다. 이는 이 도구의 보수적인 학교 공개 정책이며 법률상 일률적 금지 판정은 아닙니다.', '실제 원문 입력·저장·AI 전송 기능을 제거하고 합성 사례 또는 담당자가 검토한 비식별 집계만 사용하도록 재설계하세요. 기존 원문·임베딩·로그·백업을 조사하여 학교 담당자의 절차에 따라 접근을 차단하고 삭제하세요. 교육적 필요가 있는 민감정보 처리는 공개 앱과 분리된 승인된 업무 환경에서 별도 심사를 받으세요. 변경 후 코드 검사와 설문을 다시 실행하세요.'));
  }
  if (student && value('publicAccess') === 'yes') {
    findings.push(finding('PUBLIC_STUDENT_DATA', 'blocker', '학생 정보가 노출되는 상태에서는 공개할 수 없습니다', '학생 정보에 불특정 사용자나 다른 학생이 접근할 수 있다고 응답했습니다.', '공개 링크와 익명 조회를 차단하고 서버 권한 검증을 추가하세요. 노출 범위·캐시·다운로드 사본을 확인하고 학교 담당자에게 사고 대응을 요청하세요. 원문을 공개 이슈에 올리지 마세요.'));
  }
  if (value('sensitiveNarratives') === 'yes' && value('aiProcessing') !== 'yes') {
    findings.push(finding('SENSITIVE_DATA_REVIEW', 'high', '민감한 원문을 다루는 기능은 별도 설계 검토가 필요합니다', 'AI 사용 여부와 관계없이 자유 서술과 상담 기록은 재식별·접근 권한·보관 위험이 큽니다.', '학교 공개 기능에서 원문을 제거하고 승인된 내부 업무와 분리하세요. 담당자에게 데이터 흐름과 필요성을 검토받으세요.'));
  }
  if (student) {
    for (const [key, title, fix] of [
      ['dataMinimized', '최소 수집·비식별 검증이 필요합니다', '직접 식별자를 제거하고 날짜·반·사건·소수 집단의 결합 재식별 위험을 검토하세요. 원문 대신 범주·범위·집계를 사용하세요.'],
      ['accessControlled', '서버 접근 권한 검증이 필요합니다', '모든 읽기·수정·다운로드 API에서 사용자와 대상 학생의 권한을 확인하고 다른 계정으로 접근 차단을 테스트하세요.'],
      ['logsRedacted', '원문 로그 차단을 검증해야 합니다', '요청·응답 본문 로깅을 제거하고 오류 추적·분석 SDK·백업까지 합성 데이터로 확인하세요.'],
      ['retentionDefined', '보관·삭제 절차가 필요합니다', '항목별 보관 기간과 책임자를 정하고 백업·캐시·임베딩까지 삭제를 검증하세요.'],
      ['institutionReview', '학교 담당자의 검토가 필요합니다', '데이터 목록, 처리 목적, 접근 권한, 외부 전송과 삭제 증빙을 학교 개인정보·보안 담당자에게 검토받으세요.'],
    ]) if (value(key) === 'no') findings.push(finding(`CONTROL_${key}`, 'high', title, '실제 학생 정보를 처리하면서 해당 보호 조치가 갖춰지지 않았다고 응답했습니다.', fix));
    if (value('externalTransfer') === 'yes') findings.push(finding('EXTERNAL_TRANSFER_REVIEW', 'review', '외부 전송 경로를 확인해 주세요', '학교 밖 서비스로 학생 정보를 전송한다고 응답했습니다. 수탁자, 처리 위치, 재사용·보관 조건을 별도로 확인해야 합니다.', '학생 원문 전송을 중단하거나 최소화하고 기관 담당자에게 계약·처리 근거·보관·삭제·접근 통제를 검토받으세요.'));
  }
  if (value('realStudentData') === 'no' && value('sensitiveNarratives') === 'yes') findings.push(finding('ANSWERS_CONFLICT', 'review', '학생 정보 응답을 다시 확인해 주세요', '실제 민감 원문을 다룬다는 응답과 실제 학생 정보가 없다는 응답이 서로 맞지 않습니다.', '가명 처리된 원문도 실제 학생 정보일 수 있습니다. 데이터 흐름을 확인하여 설문을 정정하세요.'));
  if (missingAnswers.length) findings.push(finding('ANSWERS_INCOMPLETE', 'review', '확인하지 못한 항목이 있습니다', '모름이나 누락된 응답이 있어 공개 적합성을 판단할 수 없습니다.', '해당 기능의 코드·운영 설정·담당자 확인으로 미확인 항목을 채우고 다시 검사하세요.'));
  const status = statusFor(findings);
  return { status, findings, missingAnswers, summary: summaryFor(status) };
}

export function statusFor(findings) {
  return findings.some(x => x.severity === 'blocker') ? 'BLOCKED' : findings.some(x => ['high', 'medium'].includes(x.severity)) ? 'REMEDIATE' : 'REVIEW_REQUIRED';
}
export function summaryFor(status) {
  return status === 'BLOCKED' ? '현재 구조로는 학교 웹 공개 불가: 구조를 바꾼 뒤 다시 검사하세요.' : status === 'REMEDIATE' ? '수정 필요: 안내된 보호 조치를 적용하고 다시 검사하세요.' : '담당자 검토 필요: 자동 검사는 공개 승인이나 안전 인증이 아닙니다.';
}
export function combineAssessment(scan, policy) {
  const findings = [...scan.findings, ...policy.findings];
  const status = statusFor(findings);
  return { version: 1, status, summary: summaryFor(status), findings, coverage: scan.coverage, missingAnswers: policy.missingAnswers, limitations: scan.limitations };
}
