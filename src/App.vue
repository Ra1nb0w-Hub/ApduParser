<script setup lang="ts">
import { computed, ref } from 'vue';
import { parseApdu, validateCommandApdu } from './parser/apduParser';
import { flowSummaryRows, keyEmvTags } from './parser/diagnostics';
import { dolExpectedLength, isViewableTag, parseDolDataDetail, parseTagDetail } from './parser/tagDetails';
import type { DetailSection } from './parser/tagDetails';
import type { ParseResult, TlvItem } from './parser/types';

const batchApdu = ref('');
const message = ref('');
const detailDialog = ref<{ title: string; sections: DetailSection[] } | null>(null);

const parseError = computed(() => validateBatchApdu(batchApdu.value));
const apduPairs = computed(() => splitBatchApdu(batchApdu.value));
const results = computed<ParseResult[]>(() => {
  if (parseError.value) return [];
  return attachRequestDolInfo(apduPairs.value.map((item) => parseApdu(item.request, item.response)));
});

const flowRows = computed(() => flowSummaryRows(results.value));
const keyRows = computed(() => keyEmvTags(results.value));
const canExportHtml = computed(() => results.value.length > 0 && results.value.every((result) => !result.error));

function normalizedLines(text: string) {
  const lines = text.split(/\r?\n/);
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  return lines;
}

function splitBatchApdu(text: string) {
  const lines = normalizedLines(text);
  const pairs: Array<{ request: string; response: string }> = [];
  for (let i = 0; i + 1 < lines.length; i += 2) {
    pairs.push({ request: lines[i].trim(), response: lines[i + 1].trim() });
  }
  return pairs;
}

function validateBatchApdu(text: string) {
  const lines = normalizedLines(text);
  if (lines.length === 0) return '';

  for (let i = 0; i < lines.length; ++i) {
    if (!lines[i].trim()) {
      const groupIndex = Math.floor(i / 2) + 1;
      const missingType = i % 2 === 0 ? '请求' : '响应';
      return `第${groupIndex}组APDU缺少${missingType}数据。`;
    }
  }

  if (lines.length % 2 !== 0) {
    const groupIndex = Math.floor(lines.length / 2) + 1;
    const lastLineAsCommandError = validateCommandApdu(lines[lines.length - 1].trim());
    return lastLineAsCommandError ? `第${groupIndex}组APDU缺少请求数据。` : `第${groupIndex}组APDU缺少响应数据。`;
  }

  for (let i = 0; i < lines.length; i += 2) {
    const groupIndex = i / 2 + 1;
    const requestError = validateCommandApdu(lines[i].trim());
    if (requestError) return `第${groupIndex}组C-APDU数据错误：${requestError}`;

    const responseAsCommandError = validateCommandApdu(lines[i + 1].trim());
    if (!responseAsCommandError) return `第${groupIndex}组R-APDU数据疑似C-APDU，请检查请求/响应是否填反或响应数据是否错误。`;
  }
  return '';
}

function fieldValue(result: ParseResult, name: string) {
  return result.request.fields.find((field) => field.name === name)?.value ?? '';
}

function tlvValue(items: TlvItem[], tag: string) {
  return items.find((item) => item.tag === tag)?.value ?? '';
}

function responseContainsArqc(result: ParseResult) {
  const cid = tlvValue(result.response.tlvItems, '9F27');
  if (!cid) return false;
  return ((parseInt(cid.slice(0, 2), 16) >> 6) & 0x03) === 0x02;
}

function attachRequestDol(result: ParseResult, dolTag: string, dolValue: string) {
  if (!dolValue) return;
  result.requestDataDolTag = dolTag;
  result.requestDataDolValue = dolValue;

  const expectedLength = dolExpectedLength(dolValue);
  const actualLength = fieldValue(result, 'DATA').length / 2;
  if (expectedLength < 0) {
    result.requestDataDolWarning = `${dolTag}格式不完整，无法校验请求DATA长度。`;
  } else if (actualLength !== expectedLength) {
    result.requestDataDolWarning = `请求DATA长度为${actualLength}字节，${dolTag}要求长度为${expectedLength}字节，长度不匹配。`;
  }
}

function attachRequestDolInfo(items: ParseResult[]) {
  let cdol1 = '';
  let cdol2 = '';
  let generateAcCount = 0;
  let firstGacReturnedArqc = false;

  for (const result of items) {
    const ins = fieldValue(result, 'INS');
    if (ins === 'AE') {
      generateAcCount += 1;
      if (generateAcCount === 1) {
        attachRequestDol(result, '8C', cdol1);
        firstGacReturnedArqc = responseContainsArqc(result);
      } else if (firstGacReturnedArqc && cdol2) {
        attachRequestDol(result, '8D', cdol2);
      } else {
        attachRequestDol(result, '8C', cdol1);
        if (cdol1) {
          const warning = firstGacReturnedArqc ? 'CDOL2不存在，后续GAC使用CDOL1解析。' : '第一次GAC未返回ARQC，后续GAC使用CDOL1解析。';
          result.requestDataDolWarning = result.requestDataDolWarning ? `${result.requestDataDolWarning}\n${warning}` : warning;
        }
      }
    }

    for (const item of result.response.tlvItems) {
      if (item.tag === '8C') cdol1 = item.value;
      else if (item.tag === '8D') cdol2 = item.value;
    }
  }
  return items;
}

function canViewRequestData(result: ParseResult, fieldName: string, value: string) {
  return fieldName === 'DATA' && value !== '' && fieldValue(result, 'INS') === 'AE' && result.requestDataDolValue !== '';
}

function viewRequestData(result: ParseResult, value: string) {
  if (!canViewRequestData(result, 'DATA', value)) return;
  detailDialog.value = {
    title: 'GAC命令数据解析',
    sections: parseDolDataDetail(value, result.requestDataDolValue, result.requestDataDolWarning)
  };
}

function viewTag(item: TlvItem) {
  if (!isViewableTag(item.tag)) return;
  detailDialog.value = {
    title: `Tag ${item.tag}(${item.name})数据解析`,
    sections: parseTagDetail(item.tag, item.value)
  };
}

function closeDetail() {
  detailDialog.value = null;
}

function hasValueColumn(section: DetailSection) {
  return section.rows.some((row) => row.value !== undefined);
}

function detailSectionGroups(sections: DetailSection[]) {
  const groups: Array<{ title: string; sections: DetailSection[]; grouped: boolean }> = [];
  for (const section of sections) {
    if (!section.groupTitle) {
      groups.push({ title: '', sections: [section], grouped: false });
      continue;
    }
    const last = groups[groups.length - 1];
    if (last?.grouped && last.title === section.groupTitle) {
      last.sections.push(section);
    } else {
      groups.push({ title: section.groupTitle, sections: [section], grouped: true });
    }
  }
  return groups;
}

function escapeHtml(text: string | number) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function buildHtml() {
  let html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>APDU解析报告</title>';
  html += '<style>body{font-family:Arial,Microsoft YaHei,sans-serif;margin:24px;color:#222}h1{font-size:22px}h2{font-size:18px;margin-top:24px}.group{border:1px solid #B8C7D3;border-radius:6px;background:#FAFAFA;padding:12px;margin:12px 0}table{border-collapse:collapse;width:100%;margin:8px 0 18px}th,td{border:1px solid #B8C7D3;padding:6px 8px;font-size:13px;word-break:break-all}th{background:#D9EAF7}tr:nth-child(even){background:#F5F5F5}</style></head><body>';
  html += '<h1>APDU解析报告</h1>';
  html += '<div class="group"><h2>交易流程摘要</h2><table><tr><th>序号</th><th>流程</th><th>结果</th><th>说明</th></tr>';
  for (const row of flowRows.value) html += `<tr><td>${escapeHtml(row.index)}</td><td>${escapeHtml(row.step)}</td><td>${escapeHtml(row.status)}</td><td>${escapeHtml(row.detail)}</td></tr>`;
  html += '</table></div>';

  html += '<div class="group"><h2>关键 EMV 标签摘要</h2><table><tr><th>来源</th><th>Tag</th><th>名称</th><th>值</th><th>长度</th></tr>';
  for (const row of keyRows.value) html += `<tr><td>第${row.group}组</td><td>${escapeHtml(row.item.tag)}</td><td>${escapeHtml(row.item.name)}</td><td>${escapeHtml(row.item.value)}</td><td>${row.item.length}</td></tr>`;
  html += '</table></div>';

  results.value.forEach((result, index) => {
    html += `<div class="group"><h2>第${index + 1}组 APDU</h2>`;
    html += '<h3>C-APDU 数据解析</h3><table><tr><th>名称</th><th>值</th><th>含义</th></tr>';
    result.request.fields.forEach((field) => html += `<tr><td>${escapeHtml(field.name)}</td><td>${escapeHtml(field.value)}</td><td>${escapeHtml(field.description)}</td></tr>`);
    html += '</table><h3>R-APDU 数据解析</h3>';
    if (result.response.tlvItems.length === 0) {
      html += `<p>SW=${escapeHtml(result.response.sw)}，${escapeHtml(result.response.swDescription)}</p>`;
    } else {
      html += '<table><tr><th>Tag</th><th>名称</th><th>值</th><th>长度</th></tr>';
      result.response.tlvItems.forEach((item) => html += `<tr><td>${escapeHtml(item.tag)}</td><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.value)}</td><td>${item.length}</td></tr>`);
      html += '</table>';
    }
    html += '</div>';
  });

  html += '</body></html>';
  return html;
}

async function exportHtml() {
  if (!canExportHtml.value) return;
  message.value = '';
  const html = buildHtml();
  if (window.electronApi) {
    const result = await window.electronApi.saveHtml(html);
    if (!result.canceled) message.value = `HTML报告已导出：${result.filePath}`;
    return;
  }

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'apdu_report.html';
  link.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <main class="page">
    <header class="header">
      <div>
          <h1>ApduParser</h1>
      </div>
      <div class="actions">
        <button class="primary" :disabled="!canExportHtml" @click="exportHtml">导出HTML</button>
      </div>
    </header>

    <section class="input-list">
      <article class="card">
        <div class="card-title">
          <strong>输入APDU数据(Hex格式)</strong>
          <span>每两行一组：第一行为C-APDU，第二行为R-APDU</span>
        </div>
        <textarea v-model="batchApdu" class="batch-textarea" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" placeholder="例如：&#10;00A404000E ...&#10;6F23 ... 9000&#10;80A80000 ...&#10;8006 ... 9000"></textarea>
      </article>
    </section>

    <p v-if="parseError" class="error-box">{{ parseError }}</p>
    <p v-if="message" class="message">{{ message }}</p>

    <section v-if="results.length" class="result-area">
      <article class="card">
        <h2>交易流程摘要</h2>
        <table class="flow-table">
          <thead><tr><th>序号</th><th>流程</th><th>结果</th><th>说明</th></tr></thead>
          <tbody>
            <tr v-for="(row, index) in flowRows" :key="index">
              <td>{{ row.index }}</td><td>{{ row.step }}</td><td>{{ row.status }}</td><td>{{ row.detail }}</td>
            </tr>
          </tbody>
        </table>
      </article>

      <article v-if="keyRows.length" class="card">
        <h2>关键 EMV 标签摘要</h2>
        <table class="tag-table">
          <thead><tr><th>来源</th><th>Tag</th><th>名称</th><th>值</th><th>长度</th></tr></thead>
          <tbody>
            <tr v-for="row in keyRows" :key="`${row.group}-${row.item.tag}-${row.item.value}`">
              <td>第{{ row.group }}组</td><td>{{ row.item.tag }}</td><td>{{ row.item.name }}</td>
              <td>
                <button v-if="isViewableTag(row.item.tag)" class="value-link" @click="viewTag(row.item)">{{ row.item.value }}</button>
                <span v-else>{{ row.item.value }}</span>
              </td>
              <td>{{ row.item.length }}</td>
            </tr>
          </tbody>
        </table>
      </article>

      <article v-for="(result, index) in results" :key="index" class="card">
        <h2>第{{ index + 1 }}组解析结果</h2>
        <p v-if="result.error" class="error">{{ result.error }}</p>
        <h3>C-APDU 数据解析</h3>
        <table class="c-apdu-table">
          <thead><tr><th>名称</th><th>值</th><th>含义</th></tr></thead>
          <tbody>
            <tr v-for="field in result.request.fields" :key="field.name">
              <td>{{ field.name }}</td>
              <td>
                <button v-if="canViewRequestData(result, field.name, field.value)" class="value-link" @click="viewRequestData(result, field.value)">{{ field.value }}</button>
                <span v-else>{{ field.value }}</span>
              </td>
              <td>{{ field.description }}</td>
            </tr>
          </tbody>
        </table>
        <h3>R-APDU 数据解析</h3>
        <p v-if="!result.response.tlvItems.length">SW={{ result.response.sw }}，{{ result.response.swDescription }}</p>
        <table v-else class="tlv-table">
          <thead><tr><th>Tag</th><th>名称</th><th>值</th><th>长度</th></tr></thead>
          <tbody>
            <tr v-for="item in result.response.tlvItems" :key="`${item.tag}-${item.value}`">
              <td>{{ item.tag }}</td><td>{{ item.name }}</td>
              <td>
                <button v-if="isViewableTag(item.tag)" class="value-link" @click="viewTag(item)">{{ item.value }}</button>
                <span v-else>{{ item.value }}</span>
              </td>
              <td>{{ item.length }}</td>
            </tr>
          </tbody>
        </table>
      </article>
    </section>

    <div v-if="detailDialog" class="modal-mask" @click.self="closeDetail">
      <section class="modal-card">
        <header class="modal-header">
          <h2>{{ detailDialog.title }}</h2>
          <button class="small" @click="closeDetail">关闭</button>
        </header>
        <div class="modal-body">
          <article v-for="(group, groupIndex) in detailSectionGroups(detailDialog.sections)" :key="`${group.title}-${groupIndex}`" class="detail-section" :class="{ 'detail-group': group.grouped }">
            <h3 v-if="group.grouped" class="detail-group-title">{{ group.title }}</h3>
            <section v-for="section in group.sections" :key="`${section.title}-${section.rows.length}`" class="detail-subsection">
              <h4 v-if="section.title" class="detail-section-title">{{ section.title }}</h4>
              <table>
                <thead>
                  <tr v-if="hasValueColumn(section)"><th>位域</th><th>含义</th><th>值</th></tr>
                  <tr v-else><th>项目</th><th>内容</th></tr>
                </thead>
                <tbody>
                  <tr v-for="row in section.rows" :key="`${section.title}-${row.item}-${row.content}`" :class="{ active: row.active }">
                    <td>{{ row.item }}</td><td>{{ row.content }}</td><td v-if="hasValueColumn(section)">{{ row.value }}</td>
                  </tr>
                </tbody>
              </table>
            </section>
          </article>
        </div>
      </section>
    </div>
  </main>
</template>
