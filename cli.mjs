#!/usr/bin/env node
import { scanDirectory } from './src/scanner.mjs';
import { startReviewServer } from './server.mjs';

const args = process.argv.slice(2);
if (!args.length || args.includes('--help')) {
  console.log('학교 앱 안전 점검\n사용법: node cli.mjs <검사할 폴더> [--json]\n검사 대상 코드를 실행하거나 외부로 전송하지 않습니다. 실제 학생 자료는 입력하지 마세요.');
  process.exit(0);
}
if (args.length > 2 || (args[1] && args[1] !== '--json')) {
  console.error('지원하지 않는 옵션입니다. --help를 확인하세요.');
  process.exit(2);
}
try {
  const locations = new Map();
  const scan = await scanDirectory(args[0], { onFile: ({ fileId, relativePath }) => locations.set(fileId, relativePath) });
  if (args[1] === '--json') {
    console.log(JSON.stringify(scan, null, 2));
    process.exitCode = scan.status === 'BLOCKED' ? 3 : scan.status === 'REMEDIATE' ? 2 : 1;
  } else {
    const { url } = await startReviewServer(scan, locations);
    console.log('검사가 끝났습니다. 아래 주소를 이 컴퓨터의 브라우저에서 여세요.');
    console.log(url);
    console.log('주소는 이 세션의 접근키를 포함합니다. 공유하지 마세요. 종료: Ctrl+C');
  }
} catch {
  console.error('검사를 완료하지 못했습니다. 폴더 접근 권한과 Node.js 버전을 확인하세요. 경로나 원문은 출력하지 않습니다.');
  process.exitCode = 2;
}
