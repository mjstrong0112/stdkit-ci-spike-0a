#!/usr/bin/env node
/**
 * agent-guard.mjs — the stdkit PreToolUse guard for AI coding agents.
 *
 * Usage (wired by each host's hook config; never run by hand):
 *   node <repo>/scripts/agent-guard.mjs <claude-code|codex|antigravity>
 *
 * The host writes one JSON tool call to stdin. The guard denies, asks about, or
 * allows it against `.standards/guard-policy.json`, then answers in the host's
 * own encoding:
 *   - claude-code: deny/ask as `hookSpecificOutput` JSON on stdout, exit 0.
 *   - codex: exit 2 with the reason on stderr. Codex hooks cannot ask, so an
 *     ask becomes a deny that tells the agent to have the user run it.
 *   - antigravity: `{"decision":"allow"|"deny"|"force_ask"}` JSON on stdout.
 *
 * Fail-closed: any malformed input, missing or invalid policy, Node older than
 * `minNodeVersion`, script/project mismatch, or parse failure is a deny. The
 * guard is zero-dependency Node 24 ESM and calls `git` only when a push could
 * rewrite or delete a branch whose name is not on the command line.
 *
 * What it catches: force pushes, branch deletes, `--mirror`, and `--no-verify`
 * pushes onto protected branches; `git commit -n`/`--no-verify`; overriding
 * `core.hooksPath`; reading secrets (tools, shell arguments, redirects,
 * substitutions); package publishing; dependency installs and trust-surface
 * edits (ask). Shell analysis unwraps `cd`, assignments, `env`/`command`/
 * `sudo`-style wrappers, `sh|bash|zsh -c`, `eval`, `$(…)`, backticks, process
 * substitution, and expanding heredocs, up to 4 nested levels.
 *
 * Not covered (the host `permissions.deny` backstop and review cover some):
 * variable expansion, shell functions and aliases, Git aliases, `xargs` and
 * `find -exec`, `python -c`/`node -e`, `env -S`, scripts run from files or fed
 * through stdin (`bash script.sh`, `| sh`, `sh <<EOF`), `HUSKY=0`, `pnpm -w add`,
 * file arguments to `git` subcommands, and Grep over a directory with secrets.
 *
 * Edit this file only in team-standards; stdkit and adopting repositories vendor
 * a byte-identical copy whose SHA-256 the adoption pack records.
 */
import { spawnSync } from 'node:child_process';
import { accessSync, closeSync, constants, fstatSync, globSync, lstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ─── Constants ───────────────────────────────────────────────────────────────

const HOSTS = new Set(['claude-code', 'codex', 'antigravity']);
const MAX_STDIN_BYTES = 1024 * 1024;
const MAX_POLICY_BYTES = 64 * 1024;
const MAX_GLOB_MATCHES = 2000;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const MAX_SHELL_DEPTH = 4;
const GIT_TIMEOUT_MS = 2000;
const POLICY_SCHEMA_VERSION = 1;
const POLICY_RELATIVE_PATH = '.standards/guard-policy.json';
const SCRIPT_RELATIVE_PATH = 'scripts/agent-guard.mjs';
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const RANK = { allow: 0, ask: 1, deny: 2 };
/** Stands in for a command substitution inside a word; analyzed separately. */
const SUBST = '$(…)';
const POLICY_KEYS = new Set([
  'schemaVersion', 'minNodeVersion', 'protectedBranches', 'secretGlobs',
  'trustSurfaces', 'installCommands', 'denyPublishCommands',
]);
const MISSING_CODES = new Set(['ENOENT', 'ENOTDIR', 'ENAMETOOLONG']);

class GuardError extends Error {}

// ─── Verdicts ────────────────────────────────────────────────────────────────

const ALLOW = Object.freeze({ decision: 'allow', reason: '' });
const allow = () => ALLOW;
const ask = (reason) => ({ decision: 'ask', reason: `stdkit guard: ${reason}` });
const deny = (reason) => ({ decision: 'deny', reason: `stdkit guard: ${reason}` });
/** Returns `b` only when it is strictly stricter than `a`, so the first reason wins ties. */
const stricter = (a, b) => (RANK[b.decision] > RANK[a.decision] ? b : a);

// ─── Entry point ─────────────────────────────────────────────────────────────

/**
 * Runs one hook invocation and returns the process exit code. Every failure
 * after argument validation becomes a deny verdict in the host's encoding.
 */
async function main(argv) {
  const host = argv[2];
  if (argv.length !== 3 || host === undefined || !HOSTS.has(host)) {
    process.stderr.write('usage: agent-guard.mjs <claude-code|codex|antigravity>\n');
    return 2;
  }
  let verdict;
  try {
    const raw = await readStdin();
    const ctx = loadContext(host);
    verdict = decide(normalize(host, parsePayload(raw), ctx), ctx);
  } catch (error) {
    verdict = deny(`failed closed: ${error instanceof Error ? error.message : String(error)}`);
  }
  return emit(host, verdict);
}

/** Reads all of stdin, draining but discarding anything past the size cap. */
async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size <= MAX_STDIN_BYTES) chunks.push(chunk);
  }
  if (size > MAX_STDIN_BYTES) throw new GuardError(`hook input exceeds ${MAX_STDIN_BYTES} bytes`);
  return UTF8.decode(Buffer.concat(chunks));
}

// ─── Project, policy, and runtime checks ─────────────────────────────────────

/**
 * Claude Code names the project in `CLAUDE_PROJECT_DIR`; Codex and Antigravity
 * run the hook somewhere inside the repository, so walk up to the nearest `.git`.
 */
function findRepositoryRoot(host) {
  if (host === 'claude-code') {
    const dir = process.env.CLAUDE_PROJECT_DIR;
    if (dir === undefined || !path.isAbsolute(dir)) {
      throw new GuardError('CLAUDE_PROJECT_DIR must be an absolute path');
    }
    return dir;
  }
  let dir = process.cwd();
  for (;;) {
    if (safeLstat(path.join(dir, '.git')) !== undefined) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new GuardError('no Git repository found above the hook working directory');
    dir = parent;
  }
}

/**
 * Builds the compiled policy context. The running script must be this
 * project's own `scripts/agent-guard.mjs`, so a hook cannot be pointed at a
 * guard (and policy) from somewhere else.
 */
function loadContext(host) {
  const lexicalRoot = path.resolve(findRepositoryRoot(host));
  const root = realpathSync(lexicalRoot);
  const script = realpathSync(fileURLToPath(import.meta.url));
  if (script !== path.join(root, SCRIPT_RELATIVE_PATH)) {
    throw new GuardError(`running guard ${script} is not ${SCRIPT_RELATIVE_PATH} in project ${root}`);
  }
  const policy = loadPolicy(path.join(root, POLICY_RELATIVE_PATH));
  requireNode(policy.minNodeVersion);
  return {
    root,
    roots: unique([root, lexicalRoot]),
    secrets: compilePathGlobs(policy.secretGlobs),
    trust: compilePathGlobs(policy.trustSurfaces),
    protectedBranches: policy.protectedBranches.map(compileGlob),
    installs: policy.installCommands.map(splitWords),
    publish: policy.denyPublishCommands.map(splitWords),
  };
}

/** Reads the policy as a bounded regular file that is not reached through a symlink. */
function loadPolicy(file) {
  if (safeLstat(file) === undefined) throw new GuardError(`policy ${POLICY_RELATIVE_PATH} is missing`);
  if (realpathSync(file) !== file) {
    throw new GuardError(`policy ${POLICY_RELATIVE_PATH} must be a regular file, not a symlink`);
  }
  const bytes = readPolicyBytes(file);
  try {
    return validatePolicy(JSON.parse(UTF8.decode(bytes)));
  } catch (error) {
    if (error instanceof GuardError) throw error;
    throw new GuardError(`policy ${POLICY_RELATIVE_PATH} is not valid JSON`, { cause: error });
  }
}

/** Bound the read itself as well as the advertised file size. */
function readPolicyBytes(file) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new GuardError('guard policy must be a regular file');
    if (stat.size > MAX_POLICY_BYTES) throw new GuardError(`policy ${POLICY_RELATIVE_PATH} exceeds ${MAX_POLICY_BYTES} bytes`);
    const bytes = Buffer.alloc(MAX_POLICY_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const read = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset > MAX_POLICY_BYTES) throw new GuardError(`policy ${POLICY_RELATIVE_PATH} exceeds ${MAX_POLICY_BYTES} bytes`);
    return bytes.subarray(0, offset);
  } finally {
    closeSync(fd);
  }
}

/**
 * Mirrors stdkit's `GuardPolicySchema` (strict object; `denyPublishCommands`
 * defaults to `[]`). Keep the two in step.
 */
function validatePolicy(value) {
  if (!isRecord(value)) throw new GuardError('policy must be a JSON object');
  for (const key of Object.keys(value)) {
    if (!POLICY_KEYS.has(key)) throw new GuardError(`policy has unknown key ${JSON.stringify(key)}`);
  }
  if (value.schemaVersion !== POLICY_SCHEMA_VERSION) {
    throw new GuardError(`policy schemaVersion must be ${POLICY_SCHEMA_VERSION}`);
  }
  if (typeof value.minNodeVersion !== 'string' || !SEMVER.test(value.minNodeVersion)) {
    throw new GuardError('policy minNodeVersion must be major.minor.patch');
  }
  return {
    minNodeVersion: value.minNodeVersion,
    protectedBranches: stringList(value, 'protectedBranches', 1),
    secretGlobs: stringList(value, 'secretGlobs', 1),
    trustSurfaces: stringList(value, 'trustSurfaces', 1),
    installCommands: stringList(value, 'installCommands', 0),
    denyPublishCommands:
      value.denyPublishCommands === undefined ? [] : stringList(value, 'denyPublishCommands', 0),
  };
}

function stringList(record, key, min) {
  const list = record[key];
  if (!Array.isArray(list) || list.length < min || !list.every((item) => typeof item === 'string' && /\S/.test(item))) {
    throw new GuardError(`policy ${key} must be an array of at least ${min} non-empty strings`);
  }
  return list;
}

/** Compares the full major.minor.patch, not just the major version. */
function requireNode(minimum) {
  const have = SEMVER.exec(process.versions.node);
  const want = SEMVER.exec(minimum);
  if (have === null || want === null) {
    throw new GuardError(`cannot compare Node ${process.versions.node} with ${minimum}`);
  }
  for (let i = 1; i <= 3; i += 1) {
    if (have[i] === want[i]) continue;
    if (have[i].length > want[i].length || (have[i].length === want[i].length && have[i] > want[i])) return;
    throw new GuardError(`Node ${process.versions.node} is older than required ${minimum}`);
  }
}

// ─── Host payload normalization ──────────────────────────────────────────────
// A normalized call is { kind: 'read'|'edit'|'shell'|'patch'|'other', paths, command?, cwd }.

function parsePayload(raw) {
  if (raw.trim() === '') throw new GuardError('hook input is empty');
  let value;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    throw new GuardError('hook input is not valid JSON', { cause: error });
  }
  if (!isRecord(value)) throw new GuardError('hook input must be a JSON object');
  return value;
}

/** Antigravity runs the hook from `.agents/`, so its fallback cwd is the project root. */
function normalize(host, payload, ctx) {
  const fallback = host === 'antigravity' ? ctx.root : process.cwd();
  const cwd = typeof payload.cwd === 'string' && path.isAbsolute(payload.cwd) ? payload.cwd : fallback;
  if (host === 'claude-code') return normalizeClaude(payload, cwd);
  if (host === 'codex') return normalizeCodex(payload, cwd);
  return normalizeAntigravity(payload, cwd);
}

const CLAUDE_KINDS = {
  Bash: 'shell', Read: 'read', Grep: 'read', Glob: 'read',
  Edit: 'edit', Write: 'edit', MultiEdit: 'edit', NotebookEdit: 'edit',
};

function normalizeClaude(payload, cwd) {
  const tool = requireString(payload, 'tool_name');
  const input = payload.tool_input;
  if (!isRecord(input)) throw new GuardError('tool_input must be an object');
  const kind = Object.hasOwn(CLAUDE_KINDS, tool) ? CLAUDE_KINDS[tool] : 'other';
  if (kind === 'other') return { kind, paths: [], cwd };
  if (kind === 'shell') return { kind, paths: [], command: requireString(input, 'command'), cwd };
  if (tool === 'Grep') return { kind, paths: collectStrings(input, ['path', 'glob']), cwd };
  if (tool === 'Glob') return { kind, paths: collectStrings(input, ['pattern', 'path']), cwd };
  if (tool === 'NotebookEdit') return { kind, paths: [requireString(input, 'notebook_path')], cwd };
  return { kind, paths: [requireString(input, 'file_path')], cwd };
}

const CODEX_SHELL_TOOLS = new Set(['Bash', 'shell', 'exec_command', 'local_shell']);

/** Codex puts both shell commands and `apply_patch` bodies in `tool_input.command`. */
function normalizeCodex(payload, cwd) {
  const tool = requireString(payload, 'tool_name');
  const input = payload.tool_input;
  if (!isRecord(input)) throw new GuardError('tool_input must be an object');
  if (tool === 'apply_patch') {
    const paths = patchPaths(requireString(input, 'command'));
    if (paths.length === 0) throw new GuardError('apply_patch did not name any files');
    return { kind: 'edit', paths, cwd };
  }
  if (CODEX_SHELL_TOOLS.has(tool)) return { kind: 'shell', paths: [], command: commandText(input.command), cwd };
  return { kind: 'other', paths: [], cwd };
}

function commandText(value) {
  if (typeof value === 'string' && value !== '') return value;
  if (Array.isArray(value) && value.length > 0 && value.every((word) => typeof word === 'string')) {
    return value.map(shellQuote).join(' ');
  }
  throw new GuardError('tool_input.command must be a non-empty string or string array');
}

function shellQuote(word) {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`;
}

const ANTIGRAVITY_READ_TOOLS = new Set([
  'read_file', 'view_file', 'view_file_outline', 'view_code_item', 'grep_search', 'find_by_name', 'list_dir',
]);
const ANTIGRAVITY_EDIT_TOOLS = new Set([
  'edit_file', 'write_file', 'write_to_file', 'replace_file_content', 'multi_replace_file_content',
]);
const ANTIGRAVITY_PATH_KEYS = ['Path', 'TargetFile', 'AbsolutePath', 'File', 'SearchPath', 'SearchDirectory', 'DirectoryPath'];
const ANTIGRAVITY_GLOB_KEYS = ['Pattern', 'Includes'];

/** Covers both the Antigravity CLI (`read_file`, `run_command`) and IDE (`view_file`, …) tool names. */
function normalizeAntigravity(payload, cwd) {
  const toolCall = payload.toolCall;
  if (!isRecord(toolCall) || !isRecord(toolCall.args)) throw new GuardError('toolCall must be an object with args');
  const name = requireString(toolCall, 'name');
  const args = toolCall.args;
  if (name === 'run_command') {
    const command = typeof args.CommandLine === 'string' ? args.CommandLine : requireString(args, 'Command');
    const runCwd = typeof args.Cwd === 'string' && path.isAbsolute(args.Cwd) ? args.Cwd : cwd;
    return { kind: 'shell', paths: [], command, cwd: runCwd };
  }
  const read = ANTIGRAVITY_READ_TOOLS.has(name);
  if (!read && !ANTIGRAVITY_EDIT_TOOLS.has(name)) return { kind: 'other', paths: [], cwd };
  const keys = read ? [...ANTIGRAVITY_PATH_KEYS, ...ANTIGRAVITY_GLOB_KEYS] : ANTIGRAVITY_PATH_KEYS;
  const paths = collectStrings(args, keys);
  if (paths.length === 0) throw new GuardError(`${name} has no path argument`);
  return { kind: read ? 'read' : 'edit', paths, cwd };
}

// ─── Path matching ───────────────────────────────────────────────────────────

/** Minimal glob: `**` crosses directories, `*` and `?` stay within one segment. */
function compileGlob(glob) {
  let source = '';
  for (let i = 0; i < glob.length; i += 1) {
    if (glob.startsWith('/**', i) && i + 3 === glob.length) (source += '(?:/.*)?'), (i += 2);
    else if (glob.startsWith('**/', i)) (source += '(?:.*/)?'), (i += 2);
    else if (glob.startsWith('**', i)) (source += '.*'), (i += 1);
    else if (glob[i] === '*') source += '[^/]*';
    else if (glob[i] === '?') source += '[^/]';
    else source += glob[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${source}$`);
}

/** Globs without a `/` match a basename anywhere; others are anchored at the project root. */
function compilePathGlobs(globs) {
  return globs.map((glob) => {
    const pattern = glob.replace(/^\/+/, '');
    return { regex: compileGlob(pattern), basename: !pattern.includes('/') };
  });
}

function expandHome(candidate) {
  const home = process.env.HOME;
  if (home === undefined || home === '') return candidate;
  if (candidate === '~') return home;
  if (candidate.startsWith('~/')) return path.join(home, candidate.slice(2));
  return candidate;
}

/** The lexical and symlink-resolved absolute forms of a path; both must pass. */
function pathForms(candidate, cwd) {
  const lexical = path.resolve(cwd, expandHome(candidate));
  return unique([lexical, canonical(lexical)]);
}

/**
 * Resolves the deepest existing ancestor and re-appends the rest, so paths that
 * do not exist yet still canonicalize. A dangling symlink throws (deny).
 */
function canonical(absolute) {
  const tail = [];
  let current = absolute;
  for (;;) {
    if (safeLstat(current) !== undefined) return path.join(realpathSync(current), ...tail.reverse());
    const parent = path.dirname(current);
    if (parent === current) return absolute;
    tail.push(path.basename(current));
    current = parent;
  }
}

function safeLstat(file) {
  try {
    return lstatSync(file);
  } catch (error) {
    if (isRecord(error) && MISSING_CODES.has(error.code)) return undefined;
    throw error;
  }
}

function matchesAny(globs, forms, roots) {
  return forms.some((form) =>
    globs.some((glob) =>
      glob.basename
        ? glob.regex.test(path.basename(form))
        : roots.some((root) => {
            const rel = relativeInside(root, form);
            return rel !== undefined && glob.regex.test(rel);
          }),
    ),
  );
}

function relativeInside(root, file) {
  const rel = path.relative(root, file);
  if (rel === '' || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return undefined;
  return rel.split(path.sep).join('/');
}

// ─── Decision ────────────────────────────────────────────────────────────────

function decide(call, ctx) {
  let verdict = pathVerdict(call.kind, call.paths, call.cwd, ctx);
  if (call.command !== undefined) {
    verdict = stricter(verdict, pathVerdict('edit', patchPaths(call.command), call.cwd, ctx));
  }
  if (call.kind === 'shell' && verdict.decision !== 'deny') {
    verdict = stricter(verdict, analyzeShell(call.command, 0, { cwd: call.cwd }, ctx));
  }
  return verdict;
}

/** Secrets are never read or written; trust surfaces need a human for edits. */
function pathVerdict(kind, paths, cwd, ctx) {
  if (kind !== 'read' && kind !== 'edit') return allow();
  let verdict = allow();
  for (const candidate of paths) {
    if (candidate === '') continue;
    const forms = pathForms(candidate, cwd);
    if (matchesAny(ctx.secrets, forms, ctx.roots)) {
      return deny(`${kind === 'read' ? 'reading' : 'editing'} secret file ${candidate} is blocked`);
    }
    if (kind === 'edit' && matchesAny(ctx.trust, forms, ctx.roots)) {
      verdict = stricter(verdict, ask(`editing trust surface ${candidate} needs human approval`));
    }
  }
  return verdict;
}

const PATCH_FILE_LINE = /^\*\*\* (?:(?:Update|Add|Delete) File|Move to): (.+?)\s*$/gm;

/** Files named by an `apply_patch` body, whether sent as a tool or through a shell. */
function patchPaths(text) {
  if (!text.includes('*** Begin Patch')) return [];
  return [...text.matchAll(PATCH_FILE_LINE)].map((match) => match[1]);
}

// ─── Shell parsing ───────────────────────────────────────────────────────────

/**
 * Splits shell source into simple commands ({ words, redirects }) and the
 * bodies of command/process substitutions. It understands quoting, escapes,
 * line continuations, comments, operators, redirects, and heredocs; anything
 * unterminated throws so the caller fails closed.
 */
function parseShell(source) {
  const commands = [];
  const heredocs = [];
  let words = [];
  let redirects = [];
  let subs = [];
  let globs = new Set();
  let word = '';
  let inWord = false;
  let quoted = false;
  let hasGlob = false;
  let pendingRedirect;

  const append = (text, isQuoted) => {
    word += text;
    inWord = true;
    quoted ||= isQuoted;
    if (!isQuoted && /[*?[]/.test(text)) hasGlob = true;
  };
  const endWord = () => {
    if (!inWord) return;
    if (pendingRedirect === undefined) {
      words.push(word);
      if (hasGlob) globs.add(word);
    } else if (pendingRedirect !== '<<<') {
      redirects.push({ op: pendingRedirect, target: word, glob: hasGlob });
    }
    pendingRedirect = undefined;
    word = '';
    inWord = false;
    quoted = false;
    hasGlob = false;
  };
  const dropFdWord = () => {
    if (inWord && !quoted && pendingRedirect === undefined && /^\d+$/.test(word)) {
      word = '';
      inWord = false;
      hasGlob = false;
    } else {
      endWord();
    }
  };
  const endCommand = () => {
    endWord();
    if (pendingRedirect !== undefined) throw new GuardError(`redirect ${pendingRedirect} has no target`);
    if (words.length > 0 || redirects.length > 0 || subs.length > 0) {
      commands.push({ words, redirects, subs, globs });
    }
    words = [];
    redirects = [];
    subs = [];
    globs = new Set();
  };

  let i = 0;
  while (i < source.length) {
    const char = source[i];
    const next = source[i + 1];
    if (char === '\\') {
      if (next === '\n') i += 2;
      else if (next === undefined) (append('\\', true), (i += 1));
      else (append(next, true), (i += 2));
    } else if (char === "'") {
      const end = source.indexOf("'", i + 1);
      if (end === -1) throw new GuardError('unterminated single quote');
      append(source.slice(i + 1, end), true);
      i = end + 1;
    } else if (char === '"') {
      const { text, end } = readDoubleQuoted(source, i + 1, subs);
      append(text, true);
      i = end;
    } else if (char === '`') {
      const { body, end } = readBacktick(source, i + 1);
      subs.push(body);
      append(SUBST, false);
      i = end;
    } else if ((char === '$' || char === '<' || char === '>') && next === '(') {
      const end = readParen(source, i + 2);
      subs.push(source.slice(i + 2, end));
      append(SUBST, false);
      i = end + 1;
    } else if (char === '#' && !inWord) {
      const newline = source.indexOf('\n', i);
      i = newline === -1 ? source.length : newline;
    } else if (char === ' ' || char === '\t') {
      endWord();
      i += 1;
    } else if (char === '\n') {
      endCommand();
      const targetSubs = commands.at(-1)?.subs ?? subs;
      i = skipHeredocs(source, i + 1, heredocs, targetSubs);
      if (targetSubs === subs && subs.length > 0) endCommand();
    } else if (source.startsWith('<<', i) && source[i + 2] !== '<') {
      dropFdWord();
      const doc = readHeredocHead(source, i + 2);
      heredocs.push(doc);
      i = doc.end;
    } else {
      const redirect = /^(?:&>>|&>|<<<|<>|<&|>&|>>|>\||<|>)/.exec(source.slice(i, i + 3));
      if (redirect !== null) {
        dropFdWord();
        if (pendingRedirect !== undefined) throw new GuardError(`redirect ${pendingRedirect} has no target`);
        pendingRedirect = redirect[0];
        i += redirect[0].length;
      } else if (';&|()'.includes(char)) {
        endCommand();
        const pair = source.slice(i, i + 2);
        i += pair === ';;' || pair === '&&' || pair === '||' || pair === '|&' ? 2 : 1;
      } else {
        append(char, false);
        i += 1;
      }
    }
  }
  endCommand();
  return { commands };
}

/** Reads a `"…"` body from `start`; returns the unescaped text and the index after the closing quote. */
function readDoubleQuoted(source, start, substitutions) {
  let text = '';
  let i = start;
  while (i < source.length) {
    const char = source[i];
    const next = source[i + 1];
    if (char === '"') return { text, end: i + 1 };
    if (char === '\\' && next === '\n') i += 2;
    else if (char === '\\' && next !== undefined && '$`"\\'.includes(next)) (text += next), (i += 2);
    else if (char === '`') {
      const { body, end } = readBacktick(source, i + 1);
      substitutions.push(body);
      text += SUBST;
      i = end;
    } else if (char === '$' && next === '(') {
      const end = readParen(source, i + 2);
      substitutions.push(source.slice(i + 2, end));
      text += SUBST;
      i = end + 1;
    } else (text += char), (i += 1);
  }
  throw new GuardError('unterminated double quote');
}

/** Reads a backtick body from `start`; returns it unescaped and the index after the closing backtick. */
function readBacktick(source, start) {
  let body = '';
  for (let i = start; i < source.length; i += 1) {
    const char = source[i];
    const next = source[i + 1];
    if (char === '`') return { body, end: i + 1 };
    if (char === '\\' && next !== undefined && '`$\\'.includes(next)) (body += next), (i += 1);
    else body += char;
  }
  throw new GuardError('unterminated backtick substitution');
}

/**
 * Returns the index of the `)` closing a `$(`/`<(`/`>(` body that starts at
 * `start`. Quotes, comments, and heredoc bodies are skipped so their parens do not count.
 */
function readParen(source, start) {
  const heredocs = [];
  let depth = 1;
  for (let i = start; i < source.length; i += 1) {
    const char = source[i];
    if (char === '\\') i += 1;
    else if (char === "'") {
      const end = source.indexOf("'", i + 1);
      if (end === -1) break;
      i = end;
    } else if (char === '"') i = readDoubleQuoted(source, i + 1, []).end - 1;
    else if (source.startsWith('<<', i) && source[i + 2] !== '<') {
      const doc = readHeredocHead(source, i + 2);
      heredocs.push(doc);
      i = doc.end - 1;
    } else if (char === '\n' && heredocs.length > 0) i = skipHeredocs(source, i + 1, heredocs, []) - 1;
    else if (char === '#' && (i === start || /[\s;&|()]/.test(source[i - 1]))) {
      const newline = source.indexOf('\n', i);
      if (newline === -1) break;
      i = newline - 1;
    } else if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  throw new GuardError('unterminated $( substitution');
}

/** Parses the delimiter after `<<`/`<<-`; a quoted delimiter disables expansion of the body. */
function readHeredocHead(source, start) {
  let i = start;
  const strip = source[i] === '-';
  if (strip) i += 1;
  while (source[i] === ' ' || source[i] === '\t') i += 1;
  let delimiter = '';
  let quoted = false;
  while (i < source.length && !/[\s;&|()<>]/.test(source[i])) {
    const char = source[i];
    if (char === "'" || char === '"') {
      const end = source.indexOf(char, i + 1);
      if (end === -1) throw new GuardError('unterminated heredoc delimiter quote');
      delimiter += source.slice(i + 1, end);
      quoted = true;
      i = end + 1;
    } else if (char === '\\') {
      delimiter += source[i + 1] ?? '';
      quoted = true;
      i += 2;
    } else {
      delimiter += char;
      i += 1;
    }
  }
  if (delimiter === '') throw new GuardError('heredoc has no delimiter');
  return { delimiter, strip, expand: !quoted, end: i };
}

/** Consumes queued heredoc bodies from `start`; expanding bodies contribute substitutions. */
function skipHeredocs(source, start, heredocs, substitutions) {
  let i = start;
  let doc;
  while ((doc = heredocs.shift()) !== undefined) {
    let body = '';
    while (i < source.length) {
      const newline = source.indexOf('\n', i);
      const line = source.slice(i, newline === -1 ? source.length : newline);
      i = newline === -1 ? source.length : newline + 1;
      if ((doc.strip ? line.replace(/^\t+/, '') : line) === doc.delimiter) break;
      body += `${line}\n`;
    }
    if (doc.expand) collectSubstitutions(body, substitutions);
  }
  return i;
}

function collectSubstitutions(text, substitutions) {
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '\\') {
      i += 1;
    } else if (text[i] === '`') {
      const { body, end } = readBacktick(text, i + 1);
      substitutions.push(body);
      i = end - 1;
    } else if (text[i] === '$' && text[i + 1] === '(') {
      const end = readParen(text, i + 2);
      substitutions.push(text.slice(i + 2, end));
      i = end;
    }
  }
}

// ─── Shell analysis ──────────────────────────────────────────────────────────

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
/** Commands whose arguments are text, not files (so `echo .env` is fine). */
const INERT = new Set(['echo', 'printf', 'test', '[', '[[', ':', 'true', 'false', 'git']);
const WRITERS = new Set(['tee', 'cp', 'mv', 'rm', 'ln', 'install', 'truncate', 'touch', 'chmod', 'chown', 'sed', 'perl', 'dd']);
const IN_PLACE_WRITERS = new Set(['sed', 'perl']);
const OUTPUT_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>', '>&']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const RESERVED = new Set(['!', '{', '}', 'if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until']);
/** Command wrappers and the options of each that consume the following word. */
const WRAPPERS = new Map([
  ['command', []], ['builtin', []], ['nohup', []], ['time', []],
  ['exec', ['-a']], ['nice', ['-n']], ['env', ['-u', '--unset', '-C', '--chdir']],
  ['sudo', ['-u', '-g', '-C', '-h', '-p', '-U', '-r', '-t', '-D']],
]);

/** Each command evaluates its substitutions in the current `state.cwd` (`cd` updates it). */
function analyzeShell(source, depth, state, ctx) {
  if (depth > MAX_SHELL_DEPTH) return deny(`shell nesting deeper than ${MAX_SHELL_DEPTH} levels`);
  let verdict = allow();
  for (const command of parseShell(source).commands) {
    verdict = stricter(verdict, analyzeCommand(command, depth, state, ctx));
    if (verdict.decision === 'deny') return verdict;
  }
  return verdict;
}

function analyzeCommand(command, depth, state, ctx) {
  let verdict = allow();
  for (const sub of command.subs) {
    verdict = stricter(verdict, analyzeShell(sub, depth + 1, { cwd: state.cwd }, ctx));
    if (verdict.decision === 'deny') return verdict;
  }
  verdict = stricter(verdict, redirectVerdict(command.redirects, state.cwd, ctx));
  if (verdict.decision === 'deny') return verdict;
  const argv = stripWrappers(command.words);
  if (argv === null || argv.length === 0) return verdict;
  const name = path.basename(argv[0]);
  const args = argv.slice(1);
  if (name === 'cd') {
    if (args.length === 1) state.cwd = path.resolve(state.cwd, expandHome(args[0]));
    return verdict;
  }
  if (SHELLS.has(name)) return stricter(verdict, shellVerdict(args, depth, state, ctx));
  if (name === 'eval') return stricter(verdict, analyzeShell(args.join(' '), depth + 1, { cwd: state.cwd }, ctx));
  if (name === 'git') verdict = stricter(verdict, analyzeGit(args, command.globs, state, ctx));
  verdict = stricter(verdict, commandPolicyVerdict([name, ...args], ctx));
  if (verdict.decision === 'deny' || INERT.has(name)) return verdict;
  return stricter(verdict, argumentVerdict(name, args, command.globs, state.cwd, ctx));
}

/** Drops assignments, reserved words, and wrappers; returns null for `command -v`. */
function stripWrappers(words) {
  let argv = words;
  for (;;) {
    let start = 0;
    while (start < argv.length && (ASSIGNMENT.test(argv[start]) || RESERVED.has(argv[start]))) start += 1;
    argv = argv.slice(start);
    if (argv.length === 0) return argv;
    const name = path.basename(argv[0]);
    const valued = WRAPPERS.get(name);
    if (valued === undefined) return argv;
    let i = 1;
    while (i < argv.length && argv[i].startsWith('-')) {
      const option = argv[i];
      if (option === '--') {
        i += 1;
        break;
      }
      if (name === 'command' && (option === '-v' || option === '-V')) return null;
      i += valued.includes(option) ? 2 : 1;
    }
    argv = argv.slice(i);
  }
}

/** `sh -c 'script'` (and `-lc`, `-c --`, `--rcfile … -c`, …) re-enters the analyzer. */
function shellVerdict(args, depth, state, ctx) {
  let hasC = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '-o' || arg === '+o' || arg === '--rcfile' || arg === '--init-file') {
      i += 1;
    } else if (/^-[A-Za-z]*c[A-Za-z]*$/.test(arg)) {
      hasC = true;
    } else if (arg === '--' || (!arg.startsWith('-') && !arg.startsWith('+'))) {
      const script = arg === '--' ? args[i + 1] : arg;
      if (!hasC) return allow();
      return script === undefined ? deny('shell -c has no command string') : analyzeShell(script, depth + 1, { cwd: state.cwd }, ctx);
    }
  }
  return hasC ? deny('shell -c has no command string') : allow();
}

function expandTargets(value, isGlob, cwd) {
  if (!isGlob) return [value];
  let matches;
  try {
    matches = globSync(expandHome(value), { cwd, exclude: ['node_modules/**', '.git/**'] });
  } catch (error) {
    throw new GuardError(`cannot expand wildcard ${value}`, { cause: error });
  }
  if (matches.length > MAX_GLOB_MATCHES) throw new GuardError(`wildcard ${value} expands to too many paths`);
  return [value, ...matches];
}

function redirectVerdict(redirects, cwd, ctx) {
  let verdict = allow();
  for (const { op, target, glob } of redirects) {
    if ((op === '>&' || op === '<&') && /^(?:\d+-?|-)$/.test(target)) continue;
    for (const candidate of expandTargets(target, glob, cwd)) {
      const forms = pathForms(candidate, cwd);
      if (matchesAny(ctx.secrets, forms, ctx.roots)) return deny(`redirect ${op} ${candidate} touches a secret file`);
      if (OUTPUT_REDIRECTS.has(op) && matchesAny(ctx.trust, forms, ctx.roots)) {
        verdict = stricter(verdict, ask(`writing trust surface ${candidate} through ${op} needs human approval`));
      }
    }
  }
  return verdict;
}

/** Publishing is denied; an install that names a package asks. */
function commandPolicyVerdict(argv, ctx) {
  for (const prefix of ctx.publish) {
    if (startsWithWords(argv, prefix)) return deny(`${prefix.join(' ')} publishes a package and is blocked`);
  }
  for (const prefix of ctx.installs) {
    if (startsWithWords(argv, prefix) && argv.slice(prefix.length).some((arg) => !arg.startsWith('-'))) {
      return ask(`${prefix.join(' ')} changes dependencies and needs human approval`);
    }
  }
  return allow();
}

/** File-like arguments (and `--flag=value` values) must not be secrets; writers onto trust surfaces ask. */
function argumentVerdict(name, args, globs, cwd, ctx) {
  const writes =
    WRITERS.has(name) &&
    (!IN_PLACE_WRITERS.has(name) || args.some((arg) => /^-[A-Za-z]*i/.test(arg) || arg.startsWith('--in-place')));
  let verdict = allow();
  for (const arg of args) {
    const ddOperand = name === 'dd' && (arg.startsWith('if=') || arg.startsWith('of='));
    const inline = ddOperand || (arg.startsWith('--') && arg.includes('='));
    const value = inline ? arg.slice(arg.indexOf('=') + 1) : arg;
    if (value === '' || (!inline && arg.startsWith('-'))) continue;
    for (const candidate of expandTargets(value, globs.has(arg), cwd)) {
      const forms = pathForms(candidate, cwd);
      if (matchesAny(ctx.secrets, forms, ctx.roots)) return deny(`${name} ${candidate} touches a secret file`);
      if (writes && (!ddOperand || arg.startsWith('of=')) && matchesAny(ctx.trust, forms, ctx.roots)) {
        verdict = stricter(verdict, ask(`${name} modifies trust surface ${candidate} and needs human approval`));
      }
    }
  }
  return verdict;
}

// ─── Git analysis ────────────────────────────────────────────────────────────

const GIT_VALUE_OPTIONS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env', '--super-prefix', '--attr-source']);
const HOOKS_PATH = /^core\.hookspath(?:=|$)/i;
const CONFIG_READS = new Set(['--get', '--get-all', '--get-regexp', '-l', '--list']);
const GIT_WRITERS = new Set(['rm', 'mv', 'restore', 'checkout']);
const GIT_WRITER_VALUED = new Set(['-s', '--source', '-b', '-B', '--orphan', '--pathspec-from-file', '--conflict', '-U', '--unified']);
const COMMIT_VALUE_LONGS = new Set([
  '--message', '--file', '--reuse-message', '--reedit-message', '--fixup', '--squash',
  '--author', '--date', '--template', '--cleanup', '--trailer', '--pathspec-from-file',
]);
const PUSH_LONGS = [
  '--all', '--branches', '--mirror', '--tags', '--follow-tags', '--atomic', '--dry-run', '--no-dry-run',
  '--porcelain', '--delete', '--prune', '--force', '--force-with-lease', '--force-if-includes', '--repo',
  '--receive-pack', '--exec', '--push-option', '--set-upstream', '--quiet', '--verbose', '--progress',
  '--recurse-submodules', '--verify', '--no-verify', '--signed', '--ipv4', '--ipv6',
];
const PUSH_VALUE_LONGS = new Set(['--repo', '--receive-pack', '--exec', '--push-option']);

/** Walks Git's global options (keeping those that change the repository) to the subcommand. */
function analyzeGit(args, globs, state, ctx) {
  const passthrough = [];
  let gitCwd = state.cwd;
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) {
    const arg = args[i];
    const eq = arg.indexOf('=');
    const flag = arg.startsWith('--') && eq !== -1 ? arg.slice(0, eq) : arg;
    if (!GIT_VALUE_OPTIONS.has(flag)) {
      i += 1;
      continue;
    }
    const inline = flag !== arg;
    const value = inline ? arg.slice(eq + 1) : args[i + 1];
    if (value === undefined) return deny(`git ${flag} is missing its value`);
    if ((flag === '-c' || flag === '--config-env') && HOOKS_PATH.test(value)) {
      return deny('overriding core.hooksPath bypasses Git hooks');
    }
    if (flag === '-C') {
      passthrough.push('-C', value);
      gitCwd = path.resolve(gitCwd, value);
    } else if (flag === '--git-dir' || flag === '--work-tree') {
      passthrough.push(`${flag}=${value}`);
    }
    i += inline ? 1 : 2;
  }
  const subcmd = args[i];
  const rest = args.slice(i + 1);
  if (subcmd === 'commit') return commitVerdict(rest);
  if (subcmd === 'config') return configVerdict(rest);
  if (subcmd === 'push') return pushVerdict(rest, passthrough, state, ctx);
  if (GIT_WRITERS.has(subcmd)) return gitWorktreeVerdict(subcmd, rest, globs, gitCwd, ctx);
  return allow();
}

function gitWorktreeVerdict(subcmd, args, globs, cwd, ctx) {
  let afterDash = false;
  let verdict = allow();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!afterDash && arg === '--') {
      afterDash = true;
      continue;
    }
    if (!afterDash && arg.startsWith('-')) {
      if (GIT_WRITER_VALUED.has(arg)) i += 1;
      continue;
    }
    for (const candidate of expandTargets(arg, globs.has(arg), cwd)) {
      if (matchesAny(ctx.trust, pathForms(candidate, cwd), ctx.roots)) {
        verdict = stricter(verdict, ask(`git ${subcmd} modifies trust surface ${candidate} and needs human approval`));
      }
    }
  }
  return verdict;
}

/** Any unambiguous-or-not abbreviation of `--no-verify` counts, as does `-n` in a short cluster. */
function isNoVerify(flag) {
  return flag.length >= 6 && '--no-verify'.startsWith(flag);
}

function commitVerdict(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--') break;
    if (arg.startsWith('--')) {
      if (isNoVerify(arg.split('=')[0])) return deny('git commit --no-verify bypasses commit hooks');
      if (COMMIT_VALUE_LONGS.has(arg)) i += 1;
    } else if (arg.startsWith('-') && arg !== '-') {
      for (let j = 1; j < arg.length; j += 1) {
        const letter = arg[j];
        if (letter === 'n') return deny('git commit -n bypasses commit hooks');
        if ('mFcCt'.includes(letter)) {
          if (j === arg.length - 1) i += 1;
          break;
        }
        if (letter === 'u' || letter === 'S') break;
      }
    }
  }
  return allow();
}

function configVerdict(args) {
  if (!args.some((arg) => HOOKS_PATH.test(arg))) return allow();
  const flags = args.includes('--') ? args.slice(0, args.indexOf('--')) : args;
  if (args[0] === 'get' || args[0] === 'list' || flags.some((arg) => CONFIG_READS.has(arg))) return allow();
  return deny('changing core.hooksPath bypasses Git hooks');
}

function resolvePushLong(flag) {
  if (PUSH_LONGS.includes(flag)) return flag;
  const matches = PUSH_LONGS.filter((long) => long.startsWith(flag));
  return matches.length === 1 ? matches[0] : undefined;
}

/** Collects push modes and positionals, or returns a deny verdict for always-blocked flags. */
function parsePushArgs(args) {
  const mode = { force: false, remove: false, all: false, dryRun: false };
  const positionals = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--') {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const flag = resolvePushLong(eq === -1 ? arg : arg.slice(0, eq));
      if (flag === '--no-verify') return { verdict: deny('git push --no-verify bypasses push hooks') };
      if (flag === '--mirror') return { verdict: deny('git push --mirror rewrites every remote ref') };
      if (PUSH_VALUE_LONGS.has(flag) && eq === -1) i += 1;
      if (flag === '--force' || flag === '--force-with-lease' || flag === '--force-if-includes') mode.force = true;
      else if (flag === '--delete') mode.remove = true;
      else if (flag === '--prune') (mode.all = true), (mode.remove = true);
      else if (flag === '--all' || flag === '--branches') mode.all = true;
      else if (flag === '--dry-run') mode.dryRun = true;
      else if (flag === '--no-dry-run') mode.dryRun = false;
    } else if (arg.startsWith('-') && arg.length > 1) {
      for (let j = 1; j < arg.length; j += 1) {
        const letter = arg[j];
        if (letter === 'f') mode.force = true;
        else if (letter === 'd') mode.remove = true;
        else if (letter === 'n') mode.dryRun = true;
        else if (letter === 'o') {
          if (j === arg.length - 1) i += 1;
          break;
        }
      }
    } else {
      positionals.push(arg);
    }
  }
  return { mode, positionals };
}

/**
 * Block rewriting protected branches (including configured upstream, mirror,
 * push refspecs, and push.default=matching) and ask on force pushes elsewhere.
 */
function pushVerdict(args, passthrough, state, ctx) {
  const parsed = parsePushArgs(args);
  if (parsed.verdict !== undefined) return parsed.verdict;
  const { mode, positionals } = parsed;
  if (mode.dryRun) return allow();
  const remoteArg = positionals[0];
  const refspecs = positionals.slice(1);
  const implicit = { branch: null, force: false, remove: false };
  let targets = refspecs.length === 0 ? [implicit] : refspecs.map(parseRefspec);
  if (mode.all) targets = [{ branch: '*', force: false, remove: false }];
  let head;
  const getHead = () => (head === undefined ? (head = currentBranch(passthrough, state.cwd, ctx.root)) : head);
  if (refspecs.length === 0 && !mode.all) {
    if (mode.force || mode.remove) {
      const branch = getHead();
      if (branch === null) return deny('cannot resolve the current branch for a force push or delete');
      if (isProtected(branch, ctx)) return deny(`force-pushing or deleting protected branch ${branch} is blocked`);
    }
    const cfg = readPushConfig(passthrough, state.cwd, ctx.root);
    if (cfg === null) return deny('cannot read Git push configuration');
    const branch = remoteArg === undefined ? getHead() : head;
    const remote =
      remoteArg ?? cfg.get(`branch.${branch}.pushremote`)?.at(-1) ?? cfg.get(`branch.${branch}.remote`)?.at(-1) ?? 'origin';
    if (cfg.get(`remote.${remote}.mirror`)?.at(-1)?.toLowerCase() === 'true') {
      return deny(`remote ${remote} is configured as a mirror`);
    }
    const configuredPush = cfg.get(`remote.${remote}.push`) ?? [];
    if (configuredPush.length > 0) targets = configuredPush.map(parseRefspec);
    if (mode.force || mode.remove) {
      if (cfg.get('push.default')?.at(-1) === 'matching') {
        return deny('push.default=matching can force-push protected branches');
      }
      const merge = cfg.get(`branch.${getHead()}.merge`)?.at(-1)?.replace(/^refs\/heads\//, '');
      if (merge !== undefined && isProtected(merge, ctx)) {
        return deny(`force-pushing or deleting protected upstream branch ${merge} is blocked`);
      }
    }
  }
  let verdict = allow();
  for (const target of targets) {
    if (!mode.force && !mode.remove && !target.force && !target.remove) continue;
    const branch = target.branch ?? getHead();
    if (branch === null) return deny('cannot resolve the current branch for a force push or delete');
    if (isProtected(branch, ctx)) return deny(`force-pushing or deleting protected branch ${branch} is blocked`);
    if (target.branch === null) verdict = ask('a force push or delete without an explicit destination needs human approval');
    else if (mode.force || target.force) verdict = ask(`force-pushing ${branch} needs human approval`);
  }
  return verdict;
}

function parseRefspec(spec) {
  const force = spec.startsWith('+');
  const text = force ? spec.slice(1) : spec;
  const colon = text.indexOf(':');
  const destination = colon === -1 ? text : text.slice(colon + 1);
  const name = destination.replace(/^refs\/heads\//, '');
  return {
    branch: name === '' || name === 'HEAD' || name === '@' ? null : name,
    force,
    remove: colon === 0,
  };
}

/** Wildcards and unexpanded `$…` could name anything, so they count as protected. */
function isProtected(branch, ctx) {
  return branch.includes('*') || branch.includes('$') || ctx.protectedBranches.some((regex) => regex.test(branch));
}

const TRUSTED_GIT = ['/usr/bin/git', '/opt/homebrew/bin/git', '/usr/local/bin/git', '/bin/git'];
function trustedGitBin(repoRoot) {
  for (const p of TRUSTED_GIT) {
    try { const r = realpathSync(p); if (relativeInside(repoRoot, r) === undefined && statSync(r).isFile()) { accessSync(r, constants.X_OK); return r; } } catch {}
  }
  return '/usr/bin/git';
}
function runGit(gitArgs, cwd, repoRoot) {
  // A project-controlled PATH or Git environment must not select the binary or repository.
  return spawnSync(trustedGitBin(repoRoot), gitArgs, {
    cwd,
    env: { PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' },
    encoding: 'utf8',
    timeout: GIT_TIMEOUT_MS,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function currentBranch(passthrough, cwd, repoRoot) {
  const result = runGit([...passthrough, 'symbolic-ref', '--short', '-q', 'HEAD'], cwd, repoRoot);
  if (result.error !== undefined || result.status !== 0) return null;
  const branch = result.stdout.trim();
  return branch === '' ? null : branch;
}

function readPushConfig(passthrough, cwd, repoRoot) {
  const result = runGit([...passthrough, 'config', '--get-regexp', '^(?:branch\\.|remote\\.|push\\.)'], cwd, repoRoot);
  if (result.error !== undefined) return null;
  if (result.status === 1 && result.stderr === '') return new Map();
  if (result.status !== 0) return null;
  const map = new Map();
  for (const line of result.stdout.split('\n')) {
    const space = line.indexOf(' ');
    if (space === -1) continue;
    const key = line.slice(0, space);
    const list = map.get(key) ?? [];
    list.push(line.slice(space + 1));
    map.set(key, list);
  }
  return map;
}

// ─── Output ──────────────────────────────────────────────────────────────────

/** Writes the verdict in the host's hook protocol and returns the exit code. */
function emit(host, verdict) {
  if (host === 'claude-code') {
    if (verdict.decision !== 'allow') {
      const hookSpecificOutput = {
        hookEventName: 'PreToolUse',
        permissionDecision: verdict.decision,
        permissionDecisionReason: verdict.reason,
      };
      process.stdout.write(`${JSON.stringify({ hookSpecificOutput })}\n`);
    }
    return 0;
  }
  if (host === 'codex') {
    if (verdict.decision === 'allow') return 0;
    const suffix =
      verdict.decision === 'ask' ? ' Codex hooks cannot ask, so ask the user to run it themselves.' : '';
    process.stderr.write(`${verdict.reason}${suffix}\n`);
    return 2;
  }
  const decision = verdict.decision === 'ask' ? 'force_ask' : verdict.decision;
  const body = verdict.decision === 'allow' ? { decision } : { decision, reason: verdict.reason };
  process.stdout.write(`${JSON.stringify(body)}\n`);
  return 0;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const unique = (values) => [...new Set(values)];
const isRecord = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const splitWords = (text) => text.trim().split(/\s+/);
const startsWithWords = (argv, prefix) => prefix.length <= argv.length && prefix.every((word, i) => argv[i] === word);

function requireString(record, key) {
  const value = record[key];
  if (typeof value !== 'string' || value === '') throw new GuardError(`${key} must be a non-empty string`);
  return value;
}

function collectStrings(record, keys) {
  const out = [];
  for (const key of keys) {
    const value = record[key];
    if (typeof value === 'string') out.push(value);
    else if (Array.isArray(value)) out.push(...value.filter((item) => typeof item === 'string'));
  }
  return out;
}

process.exitCode = await main(process.argv);
