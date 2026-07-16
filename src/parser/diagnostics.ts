import { cryptogramTypeText, getFieldValue, tagName } from './apduParser';
import type { ParseResult, TlvItem } from './types';

function tlvValue(items: TlvItem[], tag: string): string {
  return items.find((item) => item.tag === tag)?.value ?? '';
}

function hexToBytes(hex: string): number[] {
  const normalized = hex.replace(/\s+/g, '').toUpperCase();
  const bytes: number[] = [];
  for (let i = 0; i + 1 < normalized.length; i += 2) bytes.push(parseInt(normalized.slice(i, i + 2), 16));
  return bytes;
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
}

function readDolTag(data: number[], offsetRef: { value: number }): string {
  const tagStart = offsetRef.value;
  if (offsetRef.value >= data.length) throw new Error('DOL Tag不完整。');
  const firstByte = data[offsetRef.value++];
  if ((firstByte & 0x1F) === 0x1F) {
    while (true) {
      if (offsetRef.value >= data.length) throw new Error('DOL Tag不完整。');
      const nextByte = data[offsetRef.value++];
      if ((nextByte & 0x80) === 0) break;
    }
  }
  return bytesToHex(data.slice(tagStart, offsetRef.value));
}

interface DolDataItem {
  tag: string;
  name: string;
  length: number;
  value: string;
  warning: string;
}

function parseDolDataItems(dataHex: string, dolHex: string, warnings: string[]): DolDataItem[] {
  const data = hexToBytes(dataHex);
  const dol = hexToBytes(dolHex);
  const items: DolDataItem[] = [];
  const dolOffset = { value: 0 };
  let dataOffset = 0;

  while (dolOffset.value < dol.length) {
    let tag = '';
    try {
      tag = readDolTag(dol, dolOffset);
    } catch (error) {
      warnings.push(error instanceof Error ? error.message : 'DOL Tag不完整。');
      return items;
    }

    if (dolOffset.value >= dol.length) {
      warnings.push('DOL缺少长度字段。');
      return items;
    }

    const length = dol[dolOffset.value++];
    const value = data.slice(dataOffset, dataOffset + length);
    const item: DolDataItem = {
      tag,
      name: tagName(tag),
      length,
      value: bytesToHex(value),
      warning: value.length < length ? `数据不足，缺少${length - value.length}字节` : ''
    };
    items.push(item);
    dataOffset += length;
  }

  if (dataOffset < data.length) warnings.push(`剩余未匹配数据：${bytesToHex(data.slice(dataOffset))}`);
  return items;
}

function dolItemValue(result: ParseResult, tag: string): string {
  if (!result.requestDataDolValue) return '';
  const warnings: string[] = [];
  return parseDolDataItems(getFieldValue(result, 'DATA'), result.requestDataDolValue, warnings).find((item) => item.tag === tag)?.value ?? '';
}

function resultTagValue(result: ParseResult, tag: string): string {
  return tlvValue(result.response.tlvItems, tag) || dolItemValue(result, tag);
}

function previousResultTagValue(results: ParseResult[], beforeIndex: number, tag: string): string {
  for (let i = beforeIndex - 1; i >= 0; --i) {
    const value = resultTagValue(results[i], tag);
    if (value) return value;
  }
  return '';
}

function anyResultTagValue(results: ParseResult[], preferredIndex: number, tag: string): string {
  if (preferredIndex >= 0 && preferredIndex < results.length) {
    const currentValue = resultTagValue(results[preferredIndex], tag);
    if (currentValue) return currentValue;
  }

  const previousValue = previousResultTagValue(results, preferredIndex, tag);
  if (previousValue) return previousValue;

  for (let i = preferredIndex + 1; i < results.length; ++i) {
    const value = resultTagValue(results[i], tag);
    if (value) return value;
  }
  return '';
}

function gacRequestCryptogramText(p1Hex: string): string {
  const p1 = parseInt(p1Hex || '0', 16);
  const type = p1 & 0xC0;
  if (type === 0x00) return 'AAC';
  if (type === 0x40) return 'TC';
  if (type === 0x80) return 'ARQC';
  return '预留密文类型';
}

interface BitDefinition {
  byteIndex: number;
  bit: number;
  meaning: string;
}

const tvrBits: BitDefinition[] = [
  { byteIndex: 0, bit: 7, meaning: '未执行脱机数据认证' }, { byteIndex: 0, bit: 6, meaning: '静态数据认证失败' }, { byteIndex: 0, bit: 5, meaning: '卡片数据缺失' },
  { byteIndex: 0, bit: 4, meaning: '卡片出现在终端例外文件(黑名单)中' }, { byteIndex: 0, bit: 3, meaning: '动态数据认证失败' }, { byteIndex: 0, bit: 2, meaning: '复合数据认证/应用密文生成失败' },
  { byteIndex: 1, bit: 7, meaning: 'IC卡和终端应用版本不一致' }, { byteIndex: 1, bit: 6, meaning: '应用已过期' }, { byteIndex: 1, bit: 5, meaning: '应用尚未生效' },
  { byteIndex: 1, bit: 4, meaning: '卡片不允许请求的服务' }, { byteIndex: 1, bit: 3, meaning: '新卡' },
  { byteIndex: 2, bit: 7, meaning: '持卡人验证失败' }, { byteIndex: 2, bit: 6, meaning: '未知的CVM' }, { byteIndex: 2, bit: 5, meaning: 'PIN重试次数超限' },
  { byteIndex: 2, bit: 4, meaning: '要求输入PIN，但密码键盘不存在或工作不正常' }, { byteIndex: 2, bit: 3, meaning: '要求输入PIN，密码键盘存在，但未输入PIN' }, { byteIndex: 2, bit: 2, meaning: '输入联机PIN' },
  { byteIndex: 3, bit: 7, meaning: '交易超过最低限额' }, { byteIndex: 3, bit: 6, meaning: '超过连续脱机交易下限' }, { byteIndex: 3, bit: 5, meaning: '超过连续脱机交易上限' },
  { byteIndex: 3, bit: 4, meaning: '交易被随机选择联机处理' }, { byteIndex: 3, bit: 3, meaning: '商户要求联机交易' },
  { byteIndex: 4, bit: 7, meaning: '使用缺省TDOL' }, { byteIndex: 4, bit: 6, meaning: '发卡行认证失败' }, { byteIndex: 4, bit: 5, meaning: '最后一次GENERATE AC命令之前脚本处理失败' },
  { byteIndex: 4, bit: 4, meaning: '最后一次GENERATE AC命令之后脚本处理失败' }
];

function hasTvrBit(tvrHex: string, byteIndex: number, bit: number): boolean {
  const data = hexToBytes(tvrHex);
  return data.length === 5 && (data[byteIndex] & (1 << bit)) !== 0;
}

function diagnoseTvr(hex: string): string[] {
  const data = hexToBytes(hex);
  if (data.length !== 5) return [];
  return tvrBits
    .filter((bit) => (data[bit.byteIndex] & (1 << bit.bit)) !== 0)
    .map((bit) => `TVR提示：${bit.meaning}。`);
}

function tvrIacOverlaps(iacHex: string, tvrHex: string): string[] {
  const iac = hexToBytes(iacHex);
  const tvr = hexToBytes(tvrHex);
  if (iac.length !== 5 || tvr.length !== 5) return [];

  return tvrBits
    .filter((bit) => (iac[bit.byteIndex] & (1 << bit.bit)) !== 0 && (tvr[bit.byteIndex] & (1 << bit.bit)) !== 0)
    .map((bit) => `第${bit.byteIndex + 1}字节bit${bit.bit} ${bit.meaning}`);
}

function diagnoseIacDenialOverlap(iacDenialHex: string, tvrHex: string): string[] {
  const iacDenial = hexToBytes(iacDenialHex);
  const tvr = hexToBytes(tvrHex);
  if (iacDenial.length !== 5 || tvr.length !== 5) return [];

  const overlaps = tvrIacOverlaps(iacDenialHex, tvrHex);
  if (!overlaps.length) return ['AAC拒绝分析：IAC-拒绝(9F0E)与TVR没有置位重合项。'];
  return [`AAC拒绝分析：IAC-拒绝(9F0E)与TVR存在置位重合：${overlaps.join('、')}；可作为分析卡片返回AAC的方向之一。`];
}

function diagnoseIacOnlineDefaultOverlap(iacOnlineHex: string, iacDefaultHex: string, tvrHex: string): string[] {
  const messages: string[] = [];
  const onlineOverlaps = tvrIacOverlaps(iacOnlineHex, tvrHex);
  if (onlineOverlaps.length) messages.push(`AAC拒绝分析：TVR同时命中IAC-联机(9F0F)：${onlineOverlaps.join('、')}；正常方向可能是联机，卡片仍返回AAC时建议结合IAD/CVR继续分析。`);

  const defaultOverlaps = tvrIacOverlaps(iacDefaultHex, tvrHex);
  if (defaultOverlaps.length) messages.push(`AAC拒绝分析：TVR同时命中IAC-缺省(9F0D)：${defaultOverlaps.join('、')}；若终端无法联机或走缺省行为分析，可能导致拒绝。`);
  return messages;
}

function isFilledValue(hex: string, byteHex: string): boolean {
  if (!hex || hex.length % 2 !== 0) return false;
  for (let i = 0; i < hex.length; i += 2) {
    if (hex.slice(i, i + 2).toUpperCase() !== byteHex) return false;
  }
  return true;
}

function diagnoseCdolInputForAac(result: ParseResult): string[] {
  if (!result.requestDataDolValue) return [];

  const messages: string[] = [];
  const warnings: string[] = [];
  const items = parseDolDataItems(getFieldValue(result, 'DATA'), result.requestDataDolValue, warnings);
  for (const warning of warnings) messages.push(`CDOL输入异常：${warning}`);

  const criticalTags = new Set(['95', '9B', '9F02', '9F03', '9F1A', '5F2A', '9A', '9C', '9F37', '9F35', '9F34', '9F33', '9F40']);
  for (const item of items) {
    if (!criticalTags.has(item.tag) || !item.value) continue;
    if (isFilledValue(item.value, '00')) {
      messages.push(`CDOL输入关注：关键Tag ${item.tag}(${item.name})值全为00，可能影响卡片风险判断。`);
    } else if (isFilledValue(item.value, 'FF')) {
      messages.push(`CDOL输入关注：关键Tag ${item.tag}(${item.name})值全为FF，可能是缺省填充值。`);
    }
  }
  return messages;
}

function diagnoseApplicationDataForAac(results: ParseResult[], index: number, tvr: string): string[] {
  const messages: string[] = [];
  const iad = anyResultTagValue(results, index, '9F10');
  if (iad) messages.push(`AAC拒绝分析：存在发卡行应用数据IAD(9F10)=${iad}，建议按卡组织/发卡行CVR定义进一步确认卡片内部拒绝原因。`);

  const aip = anyResultTagValue(results, index, '82');
  const aipData = hexToBytes(aip);
  if (aipData.length === 2) {
    const aipByte1 = aipData[0];
    if ((aipByte1 & 0x10) !== 0 && (hasTvrBit(tvr, 2, 7) || hasTvrBit(tvr, 2, 6) || hasTvrBit(tvr, 2, 5) || hasTvrBit(tvr, 2, 4) || hasTvrBit(tvr, 2, 3))) {
      messages.push('AAC拒绝分析：AIP显示支持持卡人验证，且TVR存在CVM/PIN相关异常，建议检查8E、9F34、9F33及PIN流程。');
    }
    if ((aipByte1 & 0x08) !== 0 && (hasTvrBit(tvr, 3, 7) || hasTvrBit(tvr, 3, 6) || hasTvrBit(tvr, 3, 5) || hasTvrBit(tvr, 3, 4) || hasTvrBit(tvr, 3, 3))) {
      messages.push('AAC拒绝分析：AIP显示支持终端风险管理，且TVR存在限额/随机联机/商户强制联机相关风险位。');
    }
    if ((aipByte1 & 0x04) !== 0 && hasTvrBit(tvr, 4, 6)) {
      messages.push('AAC拒绝分析：AIP显示支持发卡行认证，TVR显示发卡行认证失败，建议检查Tag 91及第二次GAC流程。');
    }
    if ((aipByte1 & 0x61) !== 0 && (hasTvrBit(tvr, 0, 7) || hasTvrBit(tvr, 0, 6) || hasTvrBit(tvr, 0, 5) || hasTvrBit(tvr, 0, 3) || hasTvrBit(tvr, 0, 2))) {
      messages.push('AAC拒绝分析：AIP显示支持脱机数据认证相关能力，且TVR存在ODA失败/卡片数据缺失，建议检查证书、公钥、SDA/DDA/CDA数据和READ RECORD完整性。');
    }
  }

  const pinTryCounter = anyResultTagValue(results, index, '9F17');
  if (pinTryCounter) messages.push(`AAC拒绝分析：PIN重试次数(9F17)=${pinTryCounter}；若TVR存在PIN超限或CVM失败，应重点关注PIN状态。`);

  const appExpirationDate = anyResultTagValue(results, index, '5F24');
  if (appExpirationDate && hasTvrBit(tvr, 1, 6)) messages.push(`AAC拒绝分析：应用失效日期(5F24)=${appExpirationDate}，且TVR显示应用已过期。`);

  const appEffectiveDate = anyResultTagValue(results, index, '5F25');
  if (appEffectiveDate && hasTvrBit(tvr, 1, 5)) messages.push(`AAC拒绝分析：应用生效日期(5F25)=${appEffectiveDate}，且TVR显示应用尚未生效。`);

  const auc = anyResultTagValue(results, index, '9F07');
  if (auc && hasTvrBit(tvr, 1, 4)) messages.push(`AAC拒绝分析：应用用途控制(9F07)=${auc}，且TVR显示卡片不允许请求的服务。`);
  return messages;
}

function diagnoseGacRequestReturnForAac(requestCryptogram: string): string[] {
  if (requestCryptogram === 'AAC') return ['AAC拒绝分析：本次GAC请求的就是AAC，说明终端侧已主动请求拒绝，需优先回看终端在GAC前的TVR、风险管理和CVM判断。'];
  if (requestCryptogram === 'TC') return ['AAC拒绝分析：本次GAC请求TC但卡片返回AAC，说明卡片否决了脱机批准，需重点分析卡片风险管理、IAC与IAD/CVR。'];
  if (requestCryptogram === 'ARQC') return ['AAC拒绝分析：本次GAC请求ARQC但卡片返回AAC，说明卡片拒绝联机请求，需重点分析IAD/CVR、应用状态、CVM/PIN状态及IAC-拒绝。'];
  if (requestCryptogram) return [`AAC拒绝分析：本次GAC请求${requestCryptogram}，属于非典型请求类型，需确认P1参数是否正确。`];
  return [];
}

function diagnoseAacContext(results: ParseResult[], index: number, requestCryptogram: string): string[] {
  const result = results[index];
  const tvr = resultTagValue(result, '95');
  return [
    ...diagnoseGacRequestReturnForAac(requestCryptogram),
    ...diagnoseIacDenialOverlap(previousResultTagValue(results, index, '9F0E'), tvr),
    ...diagnoseIacOnlineDefaultOverlap(previousResultTagValue(results, index, '9F0F'), previousResultTagValue(results, index, '9F0D'), tvr),
    ...diagnoseCdolInputForAac(result),
    ...diagnoseApplicationDataForAac(results, index, tvr)
  ].filter(Boolean);
}

function diagnoseTsi(hex: string): string[] {
  const data = hexToBytes(hex);
  if (data.length !== 2) return [];
  const meanings: Array<[number, string]> = [[7, '已执行脱机数据认证'], [6, '已执行持卡人验证'], [5, '已执行卡片风险管理'], [4, '已执行发卡行认证'], [3, '已执行终端风险管理'], [2, '已执行脚本处理']];
  return meanings.filter(([bit]) => (data[0] & (1 << bit)) !== 0).map(([, text]) => `TSI提示：${text}。`);
}

function cvmCodeText(code: number): string {
  switch (code & 0x3F) {
    case 0x00: return '失败CVM处理';
    case 0x01: return '明文PIN脱机验证';
    case 0x02: return '加密PIN联机验证';
    case 0x03: return '明文PIN脱机验证并签名';
    case 0x04: return '加密PIN脱机验证';
    case 0x05: return '加密PIN脱机验证并签名';
    case 0x1E: return '签名';
    case 0x1F: return '无需CVM';
    default: return 'RFU/专有CVM';
  }
}

function cvmConditionText(condition: number): string {
  switch (condition) {
    case 0x00: return '总是执行';
    case 0x01: return '如果是ATM现金交易';
    case 0x02: return '如果不是ATM现金、有人值守现金、返现交易';
    case 0x03: return '如果终端支持该CVM';
    case 0x04: return '如果是有人值守现金交易';
    case 0x05: return '如果是返现交易';
    case 0x06: return '如果交易金额小于金额X';
    case 0x07: return '如果交易金额大于金额X';
    case 0x08: return '如果交易金额小于金额Y';
    case 0x09: return '如果交易金额大于金额Y';
    default: return 'RFU/专有条件';
  }
}

function diagnoseCvmResult(hex: string): string {
  const data = hexToBytes(hex);
  if (data.length !== 3) return '';
  const result = data[2] & 0x03;
  const resultText = result === 0x01 ? '失败' : result === 0x02 ? '成功' : '未知/未执行';
  return `CVM结果：${cvmCodeText(data[0])}，条件：${cvmConditionText(data[1])}，执行结果：${resultText}。`;
}

function diagnoseResult(result: ParseResult): string[] {
  const messages: string[] = [];
  const tvr = resultTagValue(result, '95');
  messages.push(...diagnoseTvr(tvr));
  messages.push(...diagnoseTsi(tlvValue(result.response.tlvItems, '9B')));

  const cvm = resultTagValue(result, '9F34');
  const cvmMessage = diagnoseCvmResult(cvm);
  if (cvmMessage) messages.push(cvmMessage);
  return messages;
}

export interface FlowRow {
  index: string;
  step: string;
  status: string;
  detail: string;
}

export function flowSummaryRows(results: ParseResult[]): FlowRow[] {
  const rows: FlowRow[] = [];
  const warnings: string[] = [];

  results.forEach((result, index) => {
    const group = index + 1;
    const ins = getFieldValue(result, 'INS');
    let step = result.request.type || `INS ${ins}`;
    let detail = result.response.sw ? `SW=${result.response.sw}，${result.response.swDescription}` : '无状态字';

    if (ins === 'A4') {
      const data = getFieldValue(result, 'DATA');
      step = data.toUpperCase() === '315041592E5359532E4444463031' ? 'SELECT PSE目录' : 'SELECT AID';
    } else if (ins === 'A8') {
      step = 'GET PROCESSING OPTIONS';
      const afl = tlvValue(result.response.tlvItems, '94');
      if (afl) detail += `；AFL=${afl}`;
    } else if (ins === 'B2') {
      const record = parseInt(getFieldValue(result, 'P1') || '0', 16);
      const sfi = parseInt(getFieldValue(result, 'P2') || '0', 16) >> 3;
      step = `READ RECORD SFI=${sfi} Record=${record}`;
    } else if (ins === 'AE') {
      const requestCryptogram = gacRequestCryptogramText(getFieldValue(result, 'P1'));
      const cid = tlvValue(result.response.tlvItems, '9F27');
      const cryptogram = cryptogramTypeText(cid);
      step = 'GENERATE AC';
      if (requestCryptogram) {
        detail += `；请求${requestCryptogram}`;
        warnings.push(`第${group}组GAC请求${requestCryptogram}。`);
      }
      if (cryptogram) {
        detail += `；CID=${cid}，${cryptogram}`;
        if (cryptogram.startsWith('AAC')) {
          warnings.push(`第${group}组GAC返回AAC，交易被卡片拒绝。`);
          for (const message of diagnoseAacContext(results, index, requestCryptogram)) warnings.push(`第${group}组${message}`);
        }
        if (cryptogram.startsWith('ARQC')) warnings.push(`第${group}组GAC返回ARQC，交易请求联机处理。`);
      }
    }

    if (result.response.sw && result.response.sw !== '9000') {
      warnings.push(`第${group}组响应状态非9000：${result.response.sw}，${result.response.swDescription}`);
    }

    for (const message of diagnoseResult(result)) warnings.push(`第${group}组${message}`);
    rows.push({ index: String(group), step, status: result.response.sw === '9000' ? '成功' : '关注', detail });
  });

  warnings.forEach((warning) => rows.push({ index: '-', step: '诊断', status: '提示', detail: warning }));
  return rows;
}

export function keyEmvTags(results: ParseResult[]) {
  const keyTags = new Set(['4F', '50', '57', '5A', '5F24', '5F25', '82', '84', '8C', '8D', '8E', '94', '95', '9B', '9F07', '9F0D', '9F0E', '9F0F', '9F10', '9F17', '9F26', '9F27', '9F33', '9F34', '9F36', '9F38']);
  return results.flatMap((result, index) => result.response.tlvItems.filter((item) => keyTags.has(item.tag)).map((item) => ({ group: index + 1, item })));
}
