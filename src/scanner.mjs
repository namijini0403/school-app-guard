import { opendir, lstat, open, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { statusFor } from './policy.mjs';
import { secretRules } from './secret-rules.mjs';

const excluded = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__']);
const sourceExtensions = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.sh', '.ps1', '.php', '.rb', '.go', '.java', '.vue', '.svelte', '.html']);
const dataExtensions = new Set(['.json', '.jsonl', '.csv', '.tsv', '.log', '.txt', '.sql', '.xml', '.yaml', '.yml', '.env', '.toml', '.ini', '.md', '.pem', '.key', '.conf', '.config', '.properties', '.map', '.tf', '.tfvars']);
const WINDOW = 64 * 1024; // Streaming context, never a file/scan size quota.
const rule = (id, severity, pattern, title, reason, remediation, scope = 'all') => ({ id, severity, pattern, title, reason, remediation, scope });
const rules = [
  ...secretRules,
  rule('SHELL_EXECUTION', 'high', /\b(?:exec|execSync|system|popen|os\.system|subprocess\.(?:run|call|Popen))\s*\(/g, '셸·프로세스 실행 경로를 확인하세요', '실행 함수로 보이는 코드가 있습니다. 문자열에 사용자 입력이 연결되면 명령 주입이 가능하며, 이 탐지만으로 취약점이 확정되지는 않습니다.', '셸 문자열 실행을 제거하고 허용된 실행 파일과 고정 인수 배열을 사용하세요. shell:false, 입력 허용 목록, 최소 권한·격리·시간 제한을 적용하고 데이터 흐름을 검토하세요.', 'source'),
  rule('SHELL_TRUE', 'high', /\bshell\s*[:=]\s*(?:true|True)/g, '셸 해석을 켠 실행 옵션이 있습니다', '입력이 셸 문법으로 해석될 수 있는 설정이 감지되었습니다.', 'shell:false와 명시적 실행 파일·인수 배열을 사용하고 사용자 입력으로 실행 파일이나 옵션을 선택하지 못하게 하세요.', 'source'),
  rule('DYNAMIC_CODE', 'high', /\b(?:eval\s*\(|new\s+Function\s*\()/g, '동적 코드 실행을 제거하세요', '문자열을 코드로 실행하는 패턴입니다. 외부 입력이 도달하는지 별도 검토가 필요합니다.', 'JSON.parse와 고정 기능 매핑으로 대체하고 사용자·AI 응답을 실행하지 마세요.', 'source'),
  rule('RESIDENT_ID', 'high', /\b\d{6}[- ]?[1-8]\d{6}\b/g, '주민등록번호 형태의 정보가 있습니다', '식별번호 형태가 검출되었습니다. 실제 개인 식별자인지는 로컬에서 확인하세요.', '원본 값을 보고서에 복사하지 마세요. 수집 필요성을 제거하고 데이터·로그·백업·Git 이력의 노출을 담당자와 처리하세요.'),
  // A token boundary prevents restarting at every character of an oversized local part.
  // Fixed email bounds also cap domain/TLD backtracking on hostile near matches.
  rule('CONTACT_DATA', 'medium', /(?:\b01[016789][- .]?\d{3,4}[- .]?\d{4}\b|(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}(?![A-Z0-9.-]))/gi, '연락처 형태의 정보가 있습니다', '전화번호나 이메일 형태의 문자열입니다. 개발자 연락처·합성 예제일 수도 있으므로 실제 학생 정보 여부를 확인하세요.', '학생 연락처라면 공개 코드·데이터에서 제거하고 필요한 경우 권한이 제한된 별도 저장소로 분리하세요.'),
  rule('STUDENT_FIELDS', 'medium', /(?:학생\s*(?:이름|성명|학번|주소)|주민등록번호|student[_-]?(?:name|id|address)|학번\s*[:=,])/gi, '학생 식별정보 필드를 검토하세요', '학생을 식별할 수 있는 필드명으로 보이는 내용입니다. 필드명 존재만으로 실제 데이터 유출을 뜻하지는 않습니다.', '정말 필요한 항목인지 확인하고 임의 내부 ID와 별도 대응표를 사용하세요. 대응표 분리만으로 익명화가 완료되는 것은 아닙니다.'),
  rule('RAW_LOGGING', 'high', /(?:console\.(?:log|info|debug|error)|logger\.(?:info|debug|error)|logging\.(?:info|debug|error))\s*\([^\n;]{0,250}(?:req(?:uest)?\.body|response\.data|prompt|messages|student|counsel|상담)/gi, '요청·학생·AI 원문 로깅 가능성이 있습니다', '로깅 호출에 민감 원문을 담을 수 있는 변수가 함께 나타납니다. 정적 패턴이므로 실제 인수와 전송 대상을 검토해야 합니다.', '본문 로깅을 제거하고 상태·건수·무작위 요청 ID만 기록하세요. 오류 추적·분석 SDK와 보관된 로그도 확인하세요.', 'source'),
  rule('BROWSER_STORAGE', 'medium', /(?:localStorage|sessionStorage)\.setItem\s*\(/g, '브라우저 저장소 사용을 검토하세요', '브라우저 저장소는 같은 기기를 쓰는 사람이나 악성 스크립트에 노출될 수 있습니다.', '학생 원문·토큰을 브라우저 저장소에 두지 마세요. 공용 기기 종료·로그아웃 시 삭제와 서버 측 접근 권한을 검증하세요.', 'source'),
  rule('HTML_INJECTION', 'high', /(?:\.innerHTML\s*=|dangerouslySetInnerHTML|v-html\s*=)/g, 'HTML 삽입 경로를 검토하세요', '문자열 HTML 삽입은 학생 입력이나 AI 응답이 전달될 때 스크립트 실행 위험이 있습니다.', 'textContent 또는 프레임워크의 기본 텍스트 렌더링을 사용하세요. HTML이 꼭 필요하면 검증된 정화와 엄격한 CSP를 적용하세요.', 'source'),
  rule('UNSAFE_GITHUB_WORKFLOW', 'high', /(?:pull_request_target|permissions:\s*write-all)/g, 'GitHub 작업의 권한을 검토하세요', '신뢰하지 않는 PR이나 광범위한 쓰기 권한과 연결되는 설정입니다.', 'PR 코드는 비밀값 없는 읽기 전용 작업에서 검사하세요. 최소 권한, SHA 고정, persist-credentials:false를 적용하세요.'),
];

function makeFinding(rule, fileId, line) {
  const { id, severity, title, reason, remediation } = rule;
  return { id, severity, title, reason, remediation, confidence: 'pattern_signal', fileId, line };
}
export async function scanDirectory(root, options = {}) {
  if (Object.hasOwn(options, 'onFile') && typeof options.onFile !== 'function') throw new TypeError('Invalid scanner callback');
  const coverage = { filesScanned: 0, bytesScanned: 0, entriesSeen: 0, excludedDirectories: 0, skippedFiles: 0, linkedEntries: 0, unreadableEntries: 0, truncated: false, complete: false };
  const findings = [];
  let rootPath;
  let fileCounter = 0;
  let sensitiveSignal = false;
  let aiSignal = false;
  const add = item => findings.push(item);
  const fail = () => { coverage.unreadableEntries++; };
  try {
    if (typeof root !== 'string' || !root || root.includes('\0')) throw new Error();
    const stats = await lstat(root);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error();
    rootPath = await realpath(root);
  } catch { fail(); }
  const inside = candidate => { const rel = path.relative(rootPath, candidate); return !rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel); };
  // Iterative traversal: depth does not retain a chain of open directory handles.
  const pending = rootPath ? [rootPath] : [];
  while (pending.length) {
    const directory = pending.pop();
    let handle;
    try {
      const info = await lstat(directory);
      if (info.isSymbolicLink() || !inside(await realpath(directory))) { coverage.linkedEntries++; continue; }
      handle = await opendir(directory);
    } catch { fail(); continue; }
    try {
      for await (const entry of handle) {
        coverage.entriesSeen++;
        const fullPath = path.join(directory, entry.name);
        let stat;
        try {
          stat = await lstat(fullPath);
          if (stat.isSymbolicLink() || !inside(await realpath(fullPath))) { coverage.linkedEntries++; continue; }
        } catch { fail(); continue; }
        if (stat.isDirectory()) {
          if (excluded.has(entry.name.toLowerCase())) coverage.excludedDirectories++;
          else pending.push(fullPath);
          continue;
        }
        if (!stat.isFile()) { coverage.skippedFiles++; continue; }
        const extension = path.extname(entry.name).toLowerCase();
        const source = sourceExtensions.has(extension);
        const supported = source || dataExtensions.has(extension) || entry.name.startsWith('.env') || ['Dockerfile', '.gitignore', '.npmrc', 'credentials', 'config', 'id_rsa', 'id_ed25519'].includes(entry.name);
        if (!supported) { coverage.skippedFiles++; continue; }
        const fileId = `F${String(++fileCounter).padStart(5, '0')}`;
        let file;
        let bytesRead = 0;
        let valid = true;
        const localFindings = [];
        // Store only match positions for overlap deduplication, never source values.
        const seen = new Map();
        let localSensitive = false;
        let localAI = false;
        let carry = '';
        let offset = 0;
        let firstLine = 1;
        const inspect = content => {
          for (const item of rules) {
            if (item.scope === 'source' && !source) continue;
            item.pattern.lastIndex = 0;
            let match;
            let line = firstLine;
            let cursor = 0;
            while ((match = item.pattern.exec(content))) {
              for (; cursor < match.index; cursor++) if (content[cursor] === '\n') line++;
              const position = offset + match.index;
              let positions = seen.get(item.id);
              if (!positions) { positions = new Set(); seen.set(item.id, positions); }
              if (!positions.has(position)) {
                positions.add(position);
                localFindings.push(makeFinding(item, fileId, line));
              }
            }
          }
          localSensitive ||= /(?:상담\s*(?:기록|내용|원문|로그)|counsel(?:ing|ling)[_-]?(?:log|record|text)|mental[_-]?health)/i.test(content);
          localAI ||= /(?:openai|anthropic|generativelanguage|chat\.completions|responses\.create|임베딩|embedding|AI\s*분석)/i.test(content);
          const discard = Math.max(0, content.length - WINDOW);
          for (let i = 0; i < discard; i++) if (content[i] === '\n') firstLine++;
          offset += discard;
          carry = content.slice(discard);
          for (const positions of seen.values()) for (const position of positions) if (position < offset) positions.delete(position);
        };
        try {
          file = await open(fullPath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
          const opened = await file.stat();
          if (!opened.isFile() || opened.ino !== stat.ino || opened.dev !== stat.dev) { coverage.skippedFiles++; continue; }
          const buffer = Buffer.alloc(WINDOW);
          const decoder = new TextDecoder('utf-8', { fatal: true });
          // Read only the opening snapshot size; concurrent growth cannot prolong a scan forever.
          while (bytesRead < opened.size) {
            const part = await file.read(buffer, 0, Math.min(buffer.length, opened.size - bytesRead), bytesRead);
            if (!part.bytesRead) break;
            bytesRead += part.bytesRead;
            const chunk = buffer.subarray(0, part.bytesRead);
            if (chunk.includes(0)) { valid = false; break; }
            try { inspect(carry + decoder.decode(chunk, { stream: true })); }
            catch { valid = false; break; }
          }
          if (valid) {
            try { inspect(carry + decoder.decode()); } catch { valid = false; }
          }
          const afterRead = await file.stat();
          if (!valid || bytesRead !== opened.size || afterRead.size !== opened.size || afterRead.mtimeMs !== opened.mtimeMs) { coverage.skippedFiles++; continue; }
        } catch { fail(); continue; } finally { await file?.close().catch(() => {}); }
        coverage.filesScanned++;
        coverage.bytesScanned += bytesRead;
        if (options.onFile) {
          try { await options.onFile({ fileId, relativePath: path.relative(rootPath, fullPath) }); } catch { fail(); }
        }
        for (const item of localFindings) add(item);
        sensitiveSignal ||= localSensitive;
        aiSignal ||= localAI;
      }
    } catch { fail(); }
  }
  if (sensitiveSignal && aiSignal) add({ id: 'SENSITIVE_AI_SIGNALS', severity: 'high', title: '민감 원문과 AI 사용 신호가 함께 있습니다', reason: '여러 파일을 포함해 민감 기록과 AI 관련 표현이 감지되었습니다. 실제 데이터 흐름이나 실제 학생 데이터 사용을 증명하지는 않습니다.', remediation: '데이터 흐름을 로컬에서 확인하고 설문에 답하세요. 실제 학생 상담 원문을 AI가 분석한다면 공개 기능에서 제거하고 합성 사례·검토된 집계로 재설계하세요.', confidence: 'pattern_signal' });
  coverage.complete = coverage.filesScanned > 0 && !coverage.truncated && !coverage.skippedFiles && !coverage.linkedEntries && !coverage.unreadableEntries;
  if (!coverage.complete) add({ id: 'COVERAGE_INCOMPLETE', severity: 'review', title: '검사하지 못한 범위가 있습니다', reason: '지원하지 않는 파일, 링크, 변경된 파일, 접근 오류 또는 빈 입력으로 전체 범위를 확인하지 못했습니다.', remediation: '제외·누락된 범위를 별도 검토하세요. 운영 데이터베이스, 배포 설정, 저장소 이력과 바이너리도 별도 검사가 필요합니다.', confidence: 'coverage' });
  return { status: statusFor(findings), findings, coverage, limitations: [
    '정적 패턴 검사입니다. 오탐·미탐이 있으며 실제 취약점이나 비식별 완료를 인증하지 않습니다.',
    '대상 코드를 실행하거나 외부 AI·서버로 전송하지 않습니다. 보고서는 원문·파일명·경로를 포함하지 않습니다. 파일 ID는 이번 실행 내 참조용이며 로컬 화면에서만 경로 대응을 확인할 수 있습니다.',
    '.git, node_modules, 가상환경은 제외합니다. Git 이력, 설치된 의존성, 운영 DB·로그·백업·권한·네트워크 흐름은 별도 검토 대상입니다.',
    '파일 수·파일 크기·총 용량·깊이·항목 수·결과 수의 고정 한도는 없습니다. 파일은 순차 읽기하며 결과·경로 대응은 메모리를 사용합니다. 패턴 문맥은 64 Ki 문자를 겹쳐 검사하므로 매우 길게 분리된 표현은 놓칠 수 있습니다.',
    '파일 간 데이터 흐름, 난독화, 동적 코드, 압축·바이너리·UTF-8 이외 인코딩은 완전 분석하지 못합니다. 실행 중 변경되는 디렉터리는 검사하지 말고 정지된 복사본을 사용하세요.',
    '정규식은 한국어 이름, 주소, 자유 서술의 모든 개인정보를 찾지 못합니다. 식별자 삭제만으로 재식별 위험이 사라지지 않습니다.',
  ] };
}
