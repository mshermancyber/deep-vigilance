// Supply Chain Risk Scanner
// Detects dependency confusion, typosquatting, protestware, and unmaintained packages.
import { logger } from '../utils/logger.js';
import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SupplyChainFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'typosquatting' | 'dependency-confusion' | 'protestware' | 'unmaintained' | 'malicious-indicator';
  packageName: string;
  declaredVersion: string;
  ecosystem: string;
  filePath: string;
  lineNumber?: number;
  matchDetail: string;
  recommendation: string;
  references: string[];
}

export interface SupplyChainScanResult {
  projectPath: string;
  totalDependencies: number;
  ecosystems: string[];
  findings: SupplyChainFinding[];
  riskScore: number; // 0-100, higher = riskier
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    typosquatting: number;
    dependencyConfusion: number;
    protestware: number;
    unmaintained: number;
  };
}

// ---------------------------------------------------------------------------
// Top Packages by Ecosystem (embedded reference lists)
// These are the actual top-downloaded packages per ecosystem
// ---------------------------------------------------------------------------

const TOP_NPM_PACKAGES: string[] = [
  'lodash', 'chalk', 'react', 'axios', 'tslib', 'express', 'commander',
  'uuid', 'moment', 'typescript', 'date-fns', 'aws-sdk', 'ts-node',
  'webpack', 'eslint', 'prettier', 'babel-core', 'babel-runtime',
  '@angular/core', '@angular/common', '@angular/compiler', '@angular/forms',
  '@angular/platform-browser', '@angular/router', 'vue', 'next',
  'nuxt', 'gatsby', 'jest', 'mocha', 'sinon', 'cheerio', 'lodash-es',
  'rxjs', 'zone.js', 'core-js', 'regenerator-runtime', 'debug', 'supports-color',
  'has-flag', 'ansi-styles', 'color-name', 'graceful-fs', 'inherits',
  'source-map', 'glob', 'minimatch', 'brace-expansion', 'semver',
  'make-dir', 'p-limit', 'locate-path', 'find-up', 'path-exists',
  'resolve-from', 'import-fresh', 'parent-module', 'callsites',
  'strip-ansi', 'ansi-regex', 'is-fullwidth-code-point', 'string-width',
  'wrap-ansi', 'cliui', 'yargs', 'yargs-parser', 'decamelize',
  'camelcase', 'dot-prop', 'global-dirs', 'configstore', 'xdg-basedir',
  'write-file-atomic', 'signal-exit', 'shebang-command', 'shebang-regex',
  'npm-run-path', 'path-key', 'which', 'isexe', 'cross-spawn',
  'nice-try', 'p-finally', 'once', 'wrappy', 'inflight',
  'minimist', 'mkdirp', 'rimraf', 'fs-extra', 'jsonfile',
  'universalify', 'at-least-node', 'nopt', 'abbrev', 'npmlog',
  'are-we-there-yet', 'gauge', 'wide-align', 'set-blocking',
  'console-control-strings', 'strip-json-comments', 'ms', 'negotiator',
  'mime', 'mime-db', 'compressible', 'on-finished', 'ee-first',
  'depd', 'http-errors', 'statuses', 'setprototypeof', 'toidentifier',
  'ipaddr.js', 'proxy-addr', 'cookie', 'cookie-signature', 'merge-descriptors',
  'methods', 'finalhandler', 'encodeurl', 'escape-html', 'parseurl',
  'raw-body', 'iconv-lite', 'safer-buffer', 'content-type', 'type-is',
  'vary', 'accepts', 'content-disposition', 'send', 'destroy',
  'etag', 'fresh', 'range-parser', 'bytes', 'unpipe',
  'qs', 'side-channel', 'call-bind', 'get-intrinsic', 'object-inspect',
  'has-symbols', 'function-bind', 'hasown', 'es-define-property',
  'es-errors', 'gopd', 'define-data-property', 'has-property-descriptors',
  'is-callable', 'is-regex', 'is-date-object', 'is-string', 'is-number-object',
  'object-keys', 'object-assign', 'safe-buffer', 'readable-stream',
  'string_decoder', 'util-deprecate', 'process-nextick-args', 'xtend',
  'through2', 'duplexify', 'pump', 'pumpify', 'end-of-stream',
  'once', 'stream-shift', 'flush-write-stream', 'from2',
  'parallel-transform', 'ordered-read-streams', 'glob-stream',
  'glob-parent', 'micromatch', 'braces', 'fill-range', 'to-regex-range',
  'is-number', 'is-extglob', 'is-glob', 'picomatch', 'anymatch',
  'normalize-path', 'picocolors', 'postcss', 'nanoid', 'source-map-js',
  'electron-to-chromium', 'node-releases', 'update-browserslist-db',
  'caniuse-lite', 'browserslist', 'escalade', 'y18n',
  'watchpack', 'enhanced-resolve', 'tapable', 'acorn', 'ajv',
  'uri-js', 'punycode', 'loader-runner', 'schema-utils', 'json-schema-traverse',
  'fast-deep-equal', 'fast-json-stable-stringify', 'json5', 'ts-loader',
  'terser', '@jridgewell/trace-mapping', '@jridgewell/sourcemap-codec',
  '@jridgewell/gen-mapping', '@jridgewell/set-array', 'dotenv',
  'cors', 'body-parser', 'multer', 'helmet', 'morgan',
  'compression', 'passport', 'bcrypt', 'jsonwebtoken', 'joi',
  'yup', 'zod', 'class-validator', 'typeorm', 'sequelize',
  'mongoose', 'prisma', '@prisma/client', 'drizzle-orm', 'pg',
  'mysql2', 'redis', 'ioredis', 'bull', 'bullmq',
  'amqplib', 'kafkajs', 'ws', 'socket.io', 'socket.io-client',
  'graphql', 'apollo-server', '@apollo/client', 'react-dom',
  'react-router-dom', 'redux', 'react-redux', '@reduxjs/toolkit',
  'styled-components', '@emotion/react', '@emotion/styled', 'tailwindcss',
  'autoprefixer', 'postcss-import', 'postcss-nesting', 'cssnano',
  'sass', 'node-sass', 'less', 'stylus', 'classnames',
  'prop-types', 'immutable', 'reselect', 'saga', 'formik',
  'react-hook-form', 'i18next', 'react-i18next', 'react-query',
  'swr', 'zustand', 'jotai', 'valtio', 'tanstack-query',
];

const TOP_PIP_PACKAGES: string[] = [
  'pip', 'setuptools', 'wheel', 'requests', 'urllib3', 'certifi',
  'idna', 'chardet', 'six', 'python-dateutil', 'pytz', 'numpy',
  'pandas', 'scipy', 'matplotlib', 'scikit-learn', 'pillow',
  'opencv-python', 'tensorflow', 'torch', 'keras', 'transformers',
  'jupyter', 'ipython', 'ipykernel', 'notebook', 'jupyterlab',
  'flask', 'django', 'fastapi', 'uvicorn', 'gunicorn',
  'pydantic', 'sqlalchemy', 'alembic', 'psycopg2', 'pymongo',
  'redis', 'celery', 'boto3', 'botocore', 's3transfer',
  'click', 'typer', 'rich', 'colorama', 'tqdm',
  'pyyaml', 'toml', 'json5', 'orjson', 'ujson',
  'lxml', 'beautifulsoup4', 'soupsieve', 'html5lib', 'parsel',
  'scrapy', 'selenium', 'playwright', 'httpx', 'aiohttp',
  'asyncio', 'anyio', 'sniffio', 'h11', 'wsproto',
  'cryptography', 'paramiko', 'cffi', 'pycparser', 'bcrypt',
  'passlib', 'jwt', 'pyjwt', 'oauthlib', 'requests-oauthlib',
  'faker', 'factory-boy', 'hypothesis', 'pytest', 'pytest-cov',
  'coverage', 'flake8', 'black', 'isort', 'mypy',
  'pylint', 'ruff', 'bandit', 'safety', 'pip-audit',
  'virtualenv', 'poetry', 'poetry-core', 'pipenv', 'tox',
  'build', 'twine', 'pkginfo', 'readme-renderer', 'docutils',
  'pygments', 'markdown', 'mistune', 'commonmark', 'mdit-py-plugins',
  'nltk', 'spacy', 'gensim', 'textblob', 'wordcloud',
  'dask', 'distributed', 'vaex', 'modin', 'ray',
  'plotly', 'dash', 'streamlit', 'gradio', 'panel',
  'bokeh', 'altair', 'seaborn', 'plotnine', 'ggplot',
  'pyspark', 'pyarrow', 'fastparquet', 'h5py', 'netcdf4',
  'grpcio', 'grpcio-tools', 'protobuf', 'thrift', 'avro',
  'apache-beam', 'prefect', 'dagster', 'airflow', 'luigi',
  'pulp', 'ortools', 'cvxpy', 'scipy', 'sympy',
  'networkx', 'igraph', 'graph-tool', 'pyvis', 'python-louvain',
  'shapely', 'geopandas', 'folium', 'mapbox', 'cartopy',
  'pyproj', 'rasterio', 'xarray', 'rioxarray', 'netcdf4',
  'sphinx', 'sphinx-rtd-theme', 'myst-parser', 'numpydoc', 'pydocstyle',
  'mkdocs', 'mkdocs-material', 'pymdown-extensions', 'mdx-include',
  'tinify', 'PIL', 'wand', 'imageio', 'scikit-image',
  'albumentations', 'imgaug', 'torchvision', 'torchaudio', 'onnx',
  'onnxruntime', 'tensorboard', 'mlflow', 'wandb', 'dvclive',
];

const TOP_MAVEN_PACKAGES: string[] = [
  'junit:junit', 'org.junit.jupiter:junit-jupiter', 'org.junit:junit-bom',
  'org.mockito:mockito-core', 'org.mockito:mockito-inline',
  'org.assertj:assertj-core', 'org.hamcrest:hamcrest-core',
  'com.google.guava:guava', 'com.google.code.gson:gson',
  'com.fasterxml.jackson.core:jackson-databind',
  'com.fasterxml.jackson.core:jackson-core',
  'com.fasterxml.jackson.core:jackson-annotations',
  'com.fasterxml.jackson.dataformat:jackson-dataformat-xml',
  'com.fasterxml.jackson.datatype:jackson-datatype-jsr310',
  'org.apache.commons:commons-lang3', 'commons-io:commons-io',
  'commons-codec:commons-codec', 'commons-logging:commons-logging',
  'org.slf4j:slf4j-api', 'org.slf4j:slf4j-simple',
  'ch.qos.logback:logback-classic', 'ch.qos.logback:logback-core',
  'org.apache.logging.log4j:log4j-core', 'org.apache.logging.log4j:log4j-api',
  'org.springframework:spring-core', 'org.springframework:spring-context',
  'org.springframework:spring-beans', 'org.springframework:spring-web',
  'org.springframework:spring-webmvc', 'org.springframework:spring-boot',
  'org.springframework.boot:spring-boot-starter',
  'org.springframework.boot:spring-boot-starter-web',
  'org.springframework.boot:spring-boot-starter-data-jpa',
  'org.springframework.boot:spring-boot-autoconfigure',
  'org.springframework.boot:spring-boot-starter-test',
  'org.springframework.security:spring-security-core',
  'org.springframework.security:spring-security-web',
  'org.springframework.security:spring-security-config',
  'org.springframework.data:spring-data-jpa',
  'org.springframework.data:spring-data-commons',
  'org.hibernate.orm:hibernate-core', 'org.hibernate:hibernate-entitymanager',
  'org.hibernate.validator:hibernate-validator',
  'jakarta.persistence:jakarta.persistence-api',
  'jakarta.validation:jakarta.validation-api',
  'jakarta.servlet:jakarta.servlet-api',
  'org.apache.tomcat.embed:tomcat-embed-core',
  'org.apache.tomcat:tomcat-servlet-api',
  'org.eclipse.jetty:jetty-server', 'org.eclipse.jetty:jetty-servlet',
  'com.h2database:h2', 'org.postgresql:postgresql',
  'com.mysql:mysql-connector-j', 'org.mariadb.jdbc:mariadb-java-client',
  'org.flywaydb:flyway-core', 'org.liquibase:liquibase-core',
  'com.zaxxer:HikariCP', 'org.apache.tomcat:tomcat-jdbc',
  'org.mybatis:mybatis', 'org.mybatis.spring.boot:mybatis-spring-boot-starter',
  'org.apache.httpcomponents:httpclient', 'org.apache.httpcomponents:httpcore',
  'com.squareup.okhttp3:okhttp', 'com.squareup.retrofit2:retrofit',
  'com.squareup.retrofit2:converter-gson',
  'org.aspectj:aspectjweaver', 'cglib:cglib',
  'org.projectlombok:lombok', 'org.mapstruct:mapstruct',
  'org.mapstruct:mapstruct-processor',
  'io.netty:netty-all', 'io.netty:netty-buffer',
  'io.projectreactor:reactor-core', 'io.projectreactor:reactor-test',
  'org.reactivestreams:reactive-streams',
  'com.google.inject:guice', 'javax.inject:javax.inject',
  'org.apache.kafka:kafka-clients', 'org.springframework.kafka:spring-kafka',
  'org.apache.kafka:kafka-streams',
  'org.apache.activemq:activemq-broker', 'org.apache.activemq:activemq-client',
  'com.rabbitmq:amqp-client', 'org.springframework.amqp:spring-amqp',
  'org.springframework.amqp:spring-rabbit',
  'org.apache.maven.plugins:maven-compiler-plugin',
  'org.apache.maven.plugins:maven-surefire-plugin',
  'org.apache.maven.plugins:maven-jar-plugin',
  'org.apache.maven.plugins:maven-war-plugin',
  'org.apache.maven.plugins:maven-install-plugin',
  'org.apache.maven.plugins:maven-deploy-plugin',
  'io.swagger:swagger-annotations', 'io.swagger.core.v3:swagger-core',
  'io.springfox:springfox-swagger2', 'org.springdoc:springdoc-openapi-starter-webmvc-ui',
  'org.apache.commons:commons-collections4',
  'com.google.guava:failureaccess', 'com.google.guava:listenablefuture',
  'org.owasp.encoder:encoder', 'org.owasp.esapi:esapi',
  'org.jsoup:jsoup', 'org.ccil.cowan.tagsoup:tagsoup',
  'xerces:xercesImpl', 'xalan:xalan',
  'net.sf.saxon:Saxon-HE',
  'org.yaml:snakeyaml', 'com.fasterxml.jackson.dataformat:jackson-dataformat-yaml',
  'org.json:json', 'javax.json:javax.json-api',
  'com.jayway.jsonpath:json-path',
  'org.thymeleaf:thymeleaf', 'org.thymeleaf:thymeleaf-spring6',
  'org.freemarker:freemarker', 'org.apache.velocity:velocity-engine-core',
  'org.apache.poi:poi', 'org.apache.poi:poi-ooxml',
  'com.itextpdf:itext7-core', 'org.apache.pdfbox:pdfbox',
  'org.apache.tika:tika-core',
  'org.quartz-scheduler:quartz', 'org.springframework:spring-context-support',
  'com.cronutils:cron-utils',
  'org.camunda.bpm:camunda-engine',
  'io.micrometer:micrometer-core', 'io.micrometer:micrometer-registry-prometheus',
  'io.opentelemetry:opentelemetry-api',
  'io.opentelemetry:opentelemetry-sdk',
  'io.opentelemetry:opentelemetry-exporter-otlp',
  'net.logstash.logback:logstash-logback-encoder',
  'org.jacoco:jacoco-maven-plugin',
  'org.apache.maven.plugins:maven-checkstyle-plugin',
  'org.apache.maven.plugins:maven-pmd-plugin',
  'com.github.spotbugs:spotbugs-maven-plugin',
];

// Map dependencies to their ecosystem's top packages for typosquatting comparison
const TOP_PACKAGES_BY_ECOSYSTEM: Record<string, string[]> = {
  npm: TOP_NPM_PACKAGES,
  pip: TOP_PIP_PACKAGES,
  maven: TOP_MAVEN_PACKAGES,
};

// ---------------------------------------------------------------------------
// Known internal package name patterns (common prefixes suggesting internal use)
// ---------------------------------------------------------------------------

const INTERNAL_PACKAGE_PATTERNS = [
  /^internal-/i, /^@internal\//i, /^private-/i, /^@private\//i,
  /^company-/i, /^@company\//i, /^org-/i, /^@org\//i,
  /^corp-/i, /^@corp\//i, /^acme-/i, /^@acme\//i,
  /^my-/, /^app-/, /^common-/i, /^shared-/i,
  /^lib-/i, /^util-/i, /^platform-/i,
];

// ---------------------------------------------------------------------------
// Known protestware / suspicious indicators
// ---------------------------------------------------------------------------

const PROTESTWARE_INDICATORS = [
  // Install scripts that make network calls
  { pattern: /(pre|post)?install.*(?:curl|wget|fetch|http)/i, type: 'install_script_network' },
  // Postinstall that modifies files after install
  { pattern: /postinstall.*(?:rm|del|shred|wipe|overwrite|write)/i, type: 'destructive_postinstall' },
  // Packages known to have been protestware
  { pattern: /\bcolors\b/i, type: 'known_protestware', knownPackage: 'colors' },
  { pattern: /\bfaker\b/i, type: 'known_protestware', knownPackage: 'faker' },
  { pattern: /\bnode-ipc\b/i, type: 'known_protestware', knownPackage: 'node-ipc' },
  { pattern: /\beventsource\b/i, type: 'known_protestware', knownPackage: 'eventsource' },
  { pattern: /\bes5-ext\b/i, type: 'known_protestware', knownPackage: 'es5-ext' },
  // Suspicious patterns in package scripts
  { pattern: /process\.env\.(?:CI|NODE_ENV).*===.*['"]production['"'].*&&\s*(curl|wget)/i, type: 'conditional_network' },
  { pattern: /(?:curl|wget|fetch)\s+.*(?:pastebin|bit\.ly|tinyurl|is\.gd|0x0\.st)/i, type: 'suspicious_url' },
  { pattern: /(?:curl|wget|fetch)\s+.*(?:localhost|127\.0\.0\.1|169\.254)/i, type: 'internal_network_scan' },
  { pattern: /fs\.(?:writeFile|appendFile|unlink|rm|rmdir).*\b(?:package\.json|node_modules|\.git|\/etc\/|\/usr\/)/i, type: 'filesystem_manipulation' },
  // Obfuscation-like patterns
  { pattern: /eval\(.*Buffer/i, type: 'obfuscated_code' },
  { pattern: /\[.*\]\.concat\(.*require/i, type: 'obfuscated_require' },
  // Environment fingerprinting
  { pattern: /process\.env\.(?:HOME|USER|USERNAME|COMPUTERNAME|HOSTNAME)/i, type: 'environment_fingerprinting' },
];

// ---------------------------------------------------------------------------
// Known unmaintained or archived packages
// ---------------------------------------------------------------------------

const UNMAINTAINED_PACKAGES: Record<string, Array<{ name: string; ecosystem: string; lastUpdated: string; reason: string }>> = {
  npm: [
    { name: 'left-pad', ecosystem: 'npm', lastUpdated: '2020-03-01', reason: 'Deprecated — unpublishing incident' },
    { name: 'node-uuid', ecosystem: 'npm', lastUpdated: '2018-06-01', reason: 'Superseded by uuid package' },
    { name: 'gulp', ecosystem: 'npm', lastUpdated: '2021-12-01', reason: 'Build tool ecosystem shifted to webpack/esbuild' },
    { name: 'bower', ecosystem: 'npm', lastUpdated: '2019-06-01', reason: 'Deprecated in favor of npm/yarn' },
    { name: 'jade', ecosystem: 'npm', lastUpdated: '2017-12-01', reason: 'Renamed to pug' },
    { name: 'har-validator', ecosystem: 'npm', lastUpdated: '2022-08-01', reason: 'Archived by maintainer' },
    { name: 'request', ecosystem: 'npm', lastUpdated: '2020-02-01', reason: 'Deprecated — use node-fetch/axios instead' },
    { name: 'react-animate-on-scroll', ecosystem: 'npm', lastUpdated: '2021-06-01', reason: 'No longer maintained' },
    { name: 'grunt', ecosystem: 'npm', lastUpdated: '2022-10-01', reason: 'Legacy build tool, activity ceased' },
    { name: 'coffeescript', ecosystem: 'npm', lastUpdated: '2021-04-01', reason: 'Language usage declined dramatically' },
  ],
  pip: [
    { name: 'distribute', ecosystem: 'pip', lastUpdated: '2016-01-01', reason: 'Merged into setuptools' },
    { name: 'pycrypto', ecosystem: 'pip', lastUpdated: '2018-06-01', reason: 'Superseded by pycryptodome' },
    { name: 'nose', ecosystem: 'pip', lastUpdated: '2018-03-01', reason: 'Superseded by pytest' },
    { name: 'mock', ecosystem: 'pip', lastUpdated: '2022-08-01', reason: 'Integrated into unittest.mock' },
    { name: 'simplejson', ecosystem: 'pip', lastUpdated: '2022-12-01', reason: 'Superseded by built-in json (stdlib)' },
    { name: 'typing', ecosystem: 'pip', lastUpdated: '2021-05-01', reason: 'Integrated into Python 3.5+ stdlib' },
    { name: 'functools32', ecosystem: 'pip', lastUpdated: '2017-01-01', reason: 'Python 2 backport — no longer relevant' },
  ],
  maven: [
    { name: 'joda-time:joda-time', ecosystem: 'maven', lastUpdated: '2021-12-01', reason: 'Superseded by java.time (JSR-310)' },
    { name: 'javax:javaee-api', ecosystem: 'maven', lastUpdated: '2020-12-01', reason: 'Superseded by Jakarta EE' },
    { name: 'org.apache.struts:struts2-core', ecosystem: 'maven', lastUpdated: '2020-06-01', reason: 'Legacy framework, vulnerability history' },
    { name: 'org.hibernate:hibernate-entitymanager', ecosystem: 'maven', lastUpdated: '2022-06-01', reason: 'Merged into hibernate-core in 6.0' },
    { name: 'com.google.appengine:appengine-api-1.0-sdk', ecosystem: 'maven', lastUpdated: '2022-01-01', reason: 'Legacy App Engine SDK' },
  ],
};

// ---------------------------------------------------------------------------
// Levenshtein Distance
// ---------------------------------------------------------------------------

function levenshteinDistance(a: string, b: string): number {
  const alen = a.length;
  const blen = b.length;

  if (alen === 0) return blen;
  if (blen === 0) return alen;

  // Use two rows for memory efficiency
  let prevRow: number[] = [];
  let currRow: number[] = [];

  for (let j = 0; j <= blen; j++) {
    prevRow[j] = j;
  }

  for (let i = 1; i <= alen; i++) {
    currRow[0] = i;
    for (let j = 1; j <= blen; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      currRow[j] = Math.min(
        prevRow[j] + 1,           // deletion
        currRow[j - 1] + 1,       // insertion
        prevRow[j - 1] + cost,    // substitution
      );
    }
    [prevRow, currRow] = [currRow, prevRow];
  }

  return prevRow[blen];
}

// ---------------------------------------------------------------------------
// Dependency Parsers
// ---------------------------------------------------------------------------

interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: string;
  filePath: string;
  lineNumber?: number;
  hasInstallScript?: boolean;
  scripts?: Record<string, string>;
  isKnownUnmaintained?: boolean;
  unmaintainedInfo?: string;
}

function parsePackageJsonDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    const json = JSON.parse(content);
    const allDeps: Record<string, string> = {};
    let hasScripts = false;
    let scripts: Record<string, string> = {};

    // Collect all dependencies
    for (const depType of ['dependencies', 'devDependencies', 'peerDependencies']) {
      if (json[depType]) {
        Object.assign(allDeps, json[depType]);
      }
    }

    // Check for install scripts
    if (json.scripts) {
      scripts = json.scripts;
      hasScripts = true;
    }

    for (const [name, version] of Object.entries(allDeps)) {
      const ver = typeof version === 'string' ? version.replace(/^[\^~]/, '') : String(version);
      deps.push({
        name,
        version: ver,
        ecosystem: 'npm',
        filePath,
        hasInstallScript: hasScripts,
        scripts: scripts,
      });
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

function parsePomXmlDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  try {
    const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
    let match: RegExpExecArray | null;
    while ((match = depRegex.exec(content)) !== null) {
      const block = match[1]!;
      const gid = block.match(/<groupId>\s*(\S+?)\s*<\/groupId>/);
      const aid = block.match(/<artifactId>\s*(\S+?)\s*<\/artifactId>/);
      const ver = block.match(/<version>\s*(\S+?)\s*<\/version>/);
      if (gid && aid) {
        const name = `${gid[1]!}:${aid[1]!}`;
        deps.push({
          name,
          version: ver?.[1] || 'unknown',
          ecosystem: 'maven',
          filePath,
        });
      }
    }
  } catch {
    // Parse error
  }
  return deps;
}

function parseRequirementsTxtDeps(filePath: string, content: string): ParsedDependency[] {
  const deps: ParsedDependency[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const pkgMatch = line.match(/^([\w_.-]+)\s*(?:[><=!~]+\s*[\w.*-]+)?/);
    if (pkgMatch) {
      const versionMatch = line.match(/[\><=!~]{1,2}\s*([\w.*-]+)/);
      deps.push({
        name: pkgMatch[1]!,
        version: versionMatch?.[1] || 'any',
        ecosystem: 'pip',
        filePath,
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Check 1: Dependency Confusion
// ---------------------------------------------------------------------------

function checkDependencyConfusion(deps: ParsedDependency[]): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  // Dependency confusion: if a package name matches internal patterns
  // and is NOT in the top packages list, it may be a confusion risk
  for (const dep of deps) {
    const topPackages = TOP_PACKAGES_BY_ECOSYSTEM[dep.ecosystem] || [];

    // Check for internal-looking names
    const isInternalPattern = INTERNAL_PACKAGE_PATTERNS.some(p => p.test(dep.name));

    // Check if name reasonably looks like an internal package (no dots, no scope, short name)
    const looksInternal = /^[a-z][a-z0-9-]*$/.test(dep.name) && dep.name.length >= 3;

    // If it matches internal patterns but isn't in the top packages list
    if (isInternalPattern && !topPackages.includes(dep.name)) {
      findings.push({
        ruleId: 'SC-DC-001',
        title: 'Potential dependency confusion vulnerability',
        description: `Package "${dep.name}" (${dep.ecosystem}) has an internal-sounding name but is not a well-known public package. If this package name exists on a public registry, an attacker could publish a malicious version that would be installed instead of your internal package.`,
        severity: 'high',
        category: 'dependency-confusion',
        packageName: dep.name,
        declaredVersion: dep.version,
        ecosystem: dep.ecosystem,
        filePath: dep.filePath,
        lineNumber: dep.lineNumber,
        matchDetail: `Package name "${dep.name}" matches pattern for internal packages`,
        recommendation: 'Scope internal packages with a namespace prefix (e.g., @company/package for npm) and configure package registries to prioritize your private registry. Use npm scopes, pip --index-url, or Maven settings to isolate internal packages.',
        references: [
          'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610',
          'https://www.oxeye.io/blog/dependency-confusion-attack',
        ],
      });
    }

    // Flag if looks internal and completely unknown (not in top packages)
    if (looksInternal && !topPackages.includes(dep.name) && !isInternalPattern) {
      // Check if it has a common suffix pattern that suggests it's an internal project
      const internalSuffixPatterns = [/service$/i, /client$/i, /sdk$/i, /api$/i, /backend$/i, /frontend$/i, /model$/i, /util$/i, /helper$/i, /config$/i];
      const hasInternalSuffix = internalSuffixPatterns.some(p => p.test(dep.name));
      if (hasInternalSuffix) {
        findings.push({
          ruleId: 'SC-DC-002',
          title: 'Possible dependency confusion — internal naming pattern',
          description: `Package "${dep.name}" has a name pattern consistent with internal microservices/components but is not a widely-known public package.`,
          severity: 'medium',
          category: 'dependency-confusion',
          packageName: dep.name,
          declaredVersion: dep.version,
          ecosystem: dep.ecosystem,
          filePath: dep.filePath,
          lineNumber: dep.lineNumber,
          matchDetail: `Suffix pattern matched: "${dep.name}"`,
          recommendation: 'Verify this package is resolved from your private registry. Pin registry URL in your project configuration.',
          references: ['https://www.cisa.gov/dependency-confusion'],
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Check 2: Typosquatting Detection
// ---------------------------------------------------------------------------

function checkTyposquatting(deps: ParsedDependency[]): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  for (const dep of deps) {
    const topPackages = TOP_PACKAGES_BY_ECOSYSTEM[dep.ecosystem] || [];
    if (topPackages.length === 0) continue;

    // Skip if the package itself IS in the top packages
    if (topPackages.includes(dep.name)) continue;

    // Check each top package for similarity
    for (const topPkg of topPackages) {
      const distance = levenshteinDistance(dep.name.toLowerCase(), topPkg.toLowerCase());
      const lengthDiff = Math.abs(dep.name.length - topPkg.length);

      // Typosquatting threshold: Levenshtein distance of 1-2 for similar-length names
      // or 1 for names with significant length difference
      const threshold = lengthDiff <= 2 ? 2 : 1;

      if (distance > 0 && distance <= threshold) {
        // Determine the type of typosquatting
        let squattType = 'similar';
        const depName = dep.name.toLowerCase();
        const topName = topPkg.toLowerCase();

        if (depName === topName + 's' || topName === depName + 's') {
          squattType = 'plural_squatting';
        } else if (depName === topName.replace(/-/g, '') || topName === depName.replace(/-/g, '')) {
          squattType = 'hyphen_omission';
        } else if (depName.includes(topName) || topName.includes(depName)) {
          squattType = 'substring_typosquatting';
        }

        // Common typosquatting patterns
        let severity: 'high' | 'medium' = 'medium';
        if (squattType === 'plural_squatting' || squattType === 'hyphen_omission') {
          severity = 'high';
        }

        const matchDetails: string[] = [];
        matchDetails.push(`"${dep.name}" (Levenshtein distance: ${distance} from "${topPkg}")`);
        matchDetails.push(`Type: ${squattType}`);

        findings.push({
          ruleId: 'SC-TYPO-001',
          title: `Potential typosquatting — "${dep.name}" is similar to "${topPkg}"`,
          description: `Package "${dep.name}" has a name very similar to the well-known package "${topPkg}" (distance: ${distance}). This may be a typosquatting attack attempting to trick developers into installing a malicious package.`,
          severity,
          category: 'typosquatting',
          packageName: dep.name,
          declaredVersion: dep.version,
          ecosystem: dep.ecosystem,
          filePath: dep.filePath,
          lineNumber: dep.lineNumber,
          matchDetail: matchDetails.join('; '),
          recommendation: `Verify that "${dep.name}" is the intended package. If you meant to use "${topPkg}", update your dependency declaration. If "${dep.name}" is legitimate, verify its maintainer and source code before using.`,
          references: [
            'https://blog.sonatype.com/typosquatting-attacks-on-npm',
            'https://www.bleepingcomputer.com/news/security/malicious-pypi-packages-use-typosquatting-to-steal-aws-keys/',
          ],
        });
        break; // Only report the closest match
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Check 3: Protestware Indicators
// ---------------------------------------------------------------------------

function checkProtestwareIndicators(deps: ParsedDependency[]): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  const seen = new Set<string>();

  for (const dep of deps) {
    if (seen.has(dep.name)) continue;
    seen.add(dep.name);

    // Check against known protestware/flagged indicators
    const nameCheck = dep.name.toLowerCase();
    for (const indicator of PROTESTWARE_INDICATORS) {
      if (indicator.pattern.test(nameCheck) || indicator.pattern.test(dep.name)) {
        const knownPkg = (indicator as any).knownPackage;
        if (knownPkg && knownPkg.toLowerCase() === nameCheck) {
          findings.push({
            ruleId: 'SC-PROT-001',
            title: 'Known protestware package detected',
            description: `"${dep.name}" has been documented as protestware — code that alters its behavior based on geopolitical events, potentially causing destructive actions.`,
            severity: 'high',
            category: 'protestware',
            packageName: dep.name,
            declaredVersion: dep.version,
            ecosystem: dep.ecosystem,
            filePath: dep.filePath,
            lineNumber: dep.lineNumber,
            matchDetail: `Known package: ${dep.name}`,
            recommendation: `Replace "${dep.name}" with a maintained fork or alternative. If the package is required, pin to a specific safe version and monitor its behavior. Consider using package allowlists.`,
            references: [
              'https://snyk.io/blog/protestware-open-source-risks/',
              'https://www.bleepingcomputer.com/news/security/protestware-is-on-the-rise-and-its-a-growing-supply-chain-risk/',
            ],
          });
        }
      }
    }

    // Check install scripts for suspicious patterns
    if (dep.scripts) {
      for (const [scriptName, scriptContent] of Object.entries(dep.scripts)) {
        if (!scriptContent) continue;
        if (scriptName === 'preinstall' || scriptName === 'install' || scriptName === 'postinstall') {
          for (const indicator of PROTESTWARE_INDICATORS) {
            if (indicator.pattern.test(scriptContent)) {
              findings.push({
                ruleId: 'SC-PROT-002',
                title: 'Suspicious install script detected',
                description: `Package "${dep.name}" has a "${scriptName}" script that matches a suspicious pattern: ${indicator.type}. Install scripts with network calls or file system manipulation can be a sign of malicious intent or protestware.`,
                severity: 'medium',
                category: 'protestware',
                packageName: dep.name,
                declaredVersion: dep.version,
                ecosystem: dep.ecosystem,
                filePath: dep.filePath,
                lineNumber: dep.lineNumber,
                matchDetail: `Script "${scriptName}" matched pattern "${indicator.type}": ${scriptContent.slice(0, 100)}`,
                recommendation: 'Review the install script in the package source. Consider using a package with no install scripts, or use npm --ignore-scripts / pip --no-install-options.',
                references: ['https://blog.npmjs.org/post/141702188385/protecting-npm-users-through-the-supply-chain'],
              });
            }
          }
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Check 4: Unmaintained Packages
// ---------------------------------------------------------------------------

function checkUnmaintainedPackages(deps: ParsedDependency[]): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  for (const dep of deps) {
    const unmaintained = UNMAINTAINED_PACKAGES[dep.ecosystem] || [];
    for (const u of unmaintained) {
      // Check if name matches (for maven, check artifact ID suffix)
      let nameMatch = false;
      if (dep.ecosystem === 'maven') {
        // For maven, check if the unmaintained name appears in the dependency name
        nameMatch = dep.name.toLowerCase().includes(u.name.toLowerCase());
      } else {
        nameMatch = dep.name.toLowerCase() === u.name.toLowerCase();
      }

      if (nameMatch) {
        findings.push({
          ruleId: 'SC-UNMAIN-001',
          title: 'Unmaintained or deprecated package in use',
          description: `"${dep.name}" (v${dep.version}) is no longer actively maintained. Last updated: ${u.lastUpdated}. Reason: ${u.reason}. Using unmaintained packages exposes the project to unpatched vulnerabilities.`,
          severity: 'high',
          category: 'unmaintained',
          packageName: dep.name,
          declaredVersion: dep.version,
          ecosystem: dep.ecosystem,
          filePath: dep.filePath,
          lineNumber: dep.lineNumber,
          matchDetail: `Unmaintained since ${u.lastUpdated}: ${u.reason}`,
          recommendation: `Replace "${dep.name}" with the recommended alternative. ${u.reason}. Check the package repository for migration guides.`,
          references: [
            'https://endoflife.date/',
            'https://github.com/fpereiro/backlogged (npm abandoned packages tracker)',
          ],
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main Scanner
// ---------------------------------------------------------------------------

export function scanSupplyChain(projectPath: string): SupplyChainScanResult {
  logger.info({ projectPath }, 'Starting supply chain risk scan');

  const allDeps: ParsedDependency[] = [];
  const allFindings: SupplyChainFinding[] = [];

  // Parse manifests
  const manifestFiles = ['package.json', 'pom.xml', 'requirements.txt'];

  for (const mf of manifestFiles) {
    const fp = path.join(projectPath, mf);
    if (!fs.existsSync(fp)) continue;

    try {
      const content = fs.readFileSync(fp, 'utf-8');
      let deps: ParsedDependency[] = [];

      switch (mf) {
        case 'package.json':
          deps = parsePackageJsonDeps(fp, content);
          break;
        case 'pom.xml':
          deps = parsePomXmlDeps(fp, content);
          break;
        case 'requirements.txt':
          deps = parseRequirementsTxtDeps(fp, content);
          break;
      }

      allDeps.push(...deps);
    } catch (err) {
      logger.warn({ manifest: mf, err }, 'Failed to parse manifest for supply chain scan');
    }
  }

  // Run all checks
  logger.info({ totalDeps: allDeps.length }, 'Running supply chain checks');

  const confusionFindings = checkDependencyConfusion(allDeps);
  const typoFindings = checkTyposquatting(allDeps);
  const protestwareFindings = checkProtestwareIndicators(allDeps);
  const unmaintainedFindings = checkUnmaintainedPackages(allDeps);

  allFindings.push(...confusionFindings, ...typoFindings, ...protestwareFindings, ...unmaintainedFindings);

  // Compute risk score (0-100)
  const severityWeights: Record<string, number> = {
    critical: 30,
    high: 15,
    medium: 8,
    low: 3,
    info: 0,
  };

  let riskScore = 0;
  for (const finding of allFindings) {
    riskScore += severityWeights[finding.severity] || 0;
  }
  riskScore = Math.min(100, riskScore);

  // Compute ecosystem list
  const ecosystems = [...new Set(allDeps.map(d => d.ecosystem))];

  const summary = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
    typosquatting: allFindings.filter(f => f.category === 'typosquatting').length,
    dependencyConfusion: allFindings.filter(f => f.category === 'dependency-confusion').length,
    protestware: allFindings.filter(f => f.category === 'protestware').length,
    unmaintained: allFindings.filter(f => f.category === 'unmaintained').length,
  };

  return {
    projectPath,
    totalDependencies: allDeps.length,
    ecosystems,
    findings: allFindings,
    riskScore,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Utility Exports
// ---------------------------------------------------------------------------

export function getTopPackages(ecosystem: string): string[] {
  return TOP_PACKAGES_BY_ECOSYSTEM[ecosystem] || [];
}

export function getUnmaintainedPackages(ecosystem?: string): Array<{ name: string; ecosystem: string; lastUpdated: string; reason: string }> {
  if (ecosystem) {
    return UNMAINTAINED_PACKAGES[ecosystem] || [];
  }
  return Object.values(UNMAINTAINED_PACKAGES).flat();
}

export function computeLevenshtein(a: string, b: string): number {
  return levenshteinDistance(a, b);
}
