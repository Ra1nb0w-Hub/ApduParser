import { tagName } from './apduParser';

export interface DetailRow {
  item: string;
  content: string;
  value?: string;
  active?: boolean;
}

export interface DetailSection {
  title: string;
  rows: DetailRow[];
  groupTitle?: string;
}

function hexToBytes(hex: string): number[] {
  const normalized = hex.replace(/\s+/g, '').toUpperCase();
  const bytes: number[] = [];
  for (let i = 0; i < normalized.length; i += 2) bytes.push(parseInt(normalized.slice(i, i + 2), 16));
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

function parseAip(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (data.length !== 2) return [{ title: 'AIP解析', rows: [{ item: '错误', content: 'AIP长度应为2字节。' }] }];
  const byte1 = data[0];
  return [{
    title: '',
    rows: [
      { item: 'SDA支持', content: byte1 & 0x40 ? '是' : '否', active: !!(byte1 & 0x40) },
      { item: 'DDA支持', content: byte1 & 0x20 ? '是' : '否', active: !!(byte1 & 0x20) },
      { item: '持卡人验证支持', content: byte1 & 0x10 ? '是' : '否', active: !!(byte1 & 0x10) },
      { item: '终端风险管理支持', content: byte1 & 0x08 ? '是' : '否', active: !!(byte1 & 0x08) },
      { item: '发卡行认证支持', content: byte1 & 0x04 ? '是' : '否', active: !!(byte1 & 0x04) },
      { item: 'CDA支持', content: byte1 & 0x01 ? '是' : '否', active: !!(byte1 & 0x01) }
    ]
  }];
}

function parseAfl(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (!data.length || data.length % 4 !== 0) return [{ title: 'AFL解析', rows: [{ item: '错误', content: 'AFL长度必须为4字节的整数倍。' }] }];
  const rows: DetailRow[] = [];
  for (let i = 0; i < data.length; i += 4) {
    rows.push({
      item: `SFI=${data[i] >> 3}`,
      content: `第一个记录=${data[i + 1]}，最后一个记录=${data[i + 2]}，参与离线认证记录数=${data[i + 3]}`
    });
  }
  return [{ title: '', rows }];
}

function parseDol(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  const rows: DetailRow[] = [];
  const offset = { value: 0 };
  try {
    while (offset.value < data.length) {
      const tag = readDolTag(data, offset);
      if (offset.value >= data.length) throw new Error('DOL缺少长度字段。');
      const length = data[offset.value++];
      rows.push({ item: tag, content: `${tagName(tag)}，数据长度${length}字节` });
    }
  } catch (error) {
    rows.push({ item: '错误', content: error instanceof Error ? error.message : 'DOL解析失败。' });
  }
  return [{ title: '', rows: rows.length ? rows : [{ item: 'DOL', content: 'DOL为空。' }] }];
}

export function dolExpectedLength(dolHex: string): number {
  const data = hexToBytes(dolHex);
  const offset = { value: 0 };
  let totalLength = 0;
  try {
    while (offset.value < data.length) {
      readDolTag(data, offset);
      if (offset.value >= data.length) return -1;
      totalLength += data[offset.value++];
    }
  } catch {
    return -1;
  }
  return totalLength;
}

export function parseDolDataDetail(dataHex: string, dolHex: string, warning = ''): DetailSection[] {
  const data = hexToBytes(dataHex);
  const dol = hexToBytes(dolHex);
  const offset = { value: 0 };
  let dataOffset = 0;
  const rows: DetailRow[] = [];
  const warnings: DetailRow[] = warning ? warning.split('\n').map((item) => ({ item: '提示', content: item })) : [];
  const extraSections: DetailSection[] = [];

  try {
    while (offset.value < dol.length) {
      const tag = readDolTag(dol, offset);
      if (offset.value >= dol.length) throw new Error('DOL缺少长度字段。');
      const length = dol[offset.value++];
      const value = data.slice(dataOffset, dataOffset + length);
      const valueHex = bytesToHex(value);
      const missing = Math.max(0, length - value.length);
      rows.push({
        item: tag,
        content: `${tagName(tag)}，长度${length}字节，值=${valueHex}${missing ? `（数据不足，缺少${missing}字节）` : ''}`,
        active: missing > 0
      });
      if (!missing && (tag === '95' || tag === '9F33')) {
        const title = tag === '95' ? 'Tag 95 终端验证结果(TVR)解析' : 'Tag 9F33 终端能力解析';
        extraSections.push(...parseTagDetail(tag, valueHex).map((section) => ({
          groupTitle: title,
          title: section.title,
          rows: section.rows
        })));
      }
      dataOffset += length;
    }
  } catch (error) {
    warnings.push({ item: '错误', content: error instanceof Error ? error.message : 'DOL解析失败。', active: true });
  }

  if (dataOffset < data.length) warnings.push({ item: '提示', content: `剩余未匹配数据：${bytesToHex(data.slice(dataOffset))}` });
  return [
    ...(warnings.length ? [{ title: '提示', rows: warnings }] : []),
    { title: 'DOL数据明细', rows: rows.length ? rows : [{ item: 'DATA', content: dataHex }] },
    ...extraSections
  ];
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

function parseCvmList(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (data.length < 8) return [{ title: 'CVM List解析', rows: [{ item: '错误', content: 'CVM List长度至少应包含金额X、金额Y，共8字节。' }] }];
  const rows: DetailRow[] = [
    { item: '金额X', content: bytesToHex(data.slice(0, 4)) },
    { item: '金额Y', content: bytesToHex(data.slice(4, 8)) }
  ];
  const rules = data.slice(8);
  if (rules.length % 2 !== 0) {
    rows.push({ item: '错误', content: 'CVM规则长度不是2字节整数倍。' });
    return [{ title: '', rows }];
  }
  for (let i = 0; i < rules.length; i += 2) {
    const code = rules[i];
    const condition = rules[i + 1];
    const failAction = code & 0x40 ? '失败后尝试下一条CVM' : '失败后终止CVM处理';
    rows.push({ item: `CVM ${bytesToHex(rules.slice(i, i + 2))}`, content: `${cvmCodeText(code)}（${cvmConditionText(condition)}，${failAction}）` });
  }
  return [{ title: '', rows }];
}

function parseCid(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (data.length !== 1) return [{ title: 'CID解析', rows: [{ item: '错误', content: 'CID长度应为1字节。' }] }];
  const cid = data[0];
  const type = (cid >> 6) & 0x03;
  const cryptogramText = type === 0 ? 'AAC(脱机拒绝)' : type === 1 ? 'TC(脱机批准)' : type === 2 ? 'ARQC(联机请求)' : '预留';
  const advicePresent = (cid >> 3) & 0x01;
  const rows: DetailRow[] = [
    { item: '密文类型', content: cryptogramText },
    { item: '是否存在建议代码', content: advicePresent ? '存在' : '不存在', active: !!advicePresent }
  ];
  if (advicePresent) {
    const advice = cid & 0x07;
    const adviceText = advice === 0 ? '未提供信息' : advice === 1 ? '服务不允许' : advice === 2 ? 'PIN尝试次数已超出限制' : advice === 3 ? '发卡行认证失败' : '预留';
    rows.push({ item: '建议代码', content: adviceText, active: true });
  }
  return [{ title: '', rows }];
}

const tvrBits = [
  [7, '数据认证结果', '未执行脱机数据认证'], [6, '数据认证结果', '静态数据认证失败'], [5, '数据认证结果', '卡片数据缺失'], [4, '数据认证结果', '卡片出现在终端例外文件(黑名单)中'], [3, '数据认证结果', '动态数据认证失败'], [2, '数据认证结果', '复合数据认证/应用密文生成失败'], [1, '数据认证结果', '保留位'], [0, '数据认证结果', '保留位'],
  [15, '处理限制结果', 'IC卡和终端应用版本不一致'], [14, '处理限制结果', '应用已过期'], [13, '处理限制结果', '应用尚未生效'], [12, '处理限制结果', '卡片不允许请求的服务'], [11, '处理限制结果', '新卡'], [10, '处理限制结果', '保留位'], [9, '处理限制结果', '保留位'], [8, '处理限制结果', '保留位'],
  [23, '持卡人认证结果', '持卡人验证失败'], [22, '持卡人认证结果', '未知的CVM'], [21, '持卡人认证结果', 'PIN重试次数超限'], [20, '持卡人认证结果', '要求输入PIN，但密码键盘不存在或工作不正常'], [19, '持卡人认证结果', '要求输入PIN，密码键盘存在，但未输入PIN'], [18, '持卡人认证结果', '输入联机PIN'], [17, '持卡人认证结果', '保留位'], [16, '持卡人认证结果', '保留位'],
  [31, '风险管理结果', '交易超过最低限额'], [30, '风险管理结果', '超过连续脱机交易下限'], [29, '风险管理结果', '超过连续脱机交易上限'], [28, '风险管理结果', '交易被随机选择联机处理'], [27, '风险管理结果', '商户要求联机交易'], [26, '风险管理结果', '保留位'], [25, '风险管理结果', '保留位'], [24, '风险管理结果', '保留位'],
  [39, '行为分析结果', '使用缺省TDOL'], [38, '行为分析结果', '发卡行认证失败'], [37, '行为分析结果', '最后一次GENERATE AC命令之前脚本处理失败'], [36, '行为分析结果', '最后一次GENERATE AC命令之后脚本处理失败'], [35, '行为分析结果', '保留位'], [34, '行为分析结果', '保留位'], [33, '行为分析结果', '保留位'], [32, '行为分析结果', '保留位']
] as const;

function parseTvrLike(tag: string, hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (data.length !== 5) return [{ title: `${tag}解析`, rows: [{ item: '错误', content: `${tag === '95' ? 'TVR' : 'IAC'}长度应为5字节。` }] }];
  const sections = ['第1字节: 数据认证结果', '第2字节: 处理限制结果', '第3字节: 持卡人认证结果', '第4字节: 风险管理结果', '第5字节: 行为分析结果'];
  return sections.map((title, byteIndex) => ({
    title,
    rows: tvrBits.slice(byteIndex * 8, byteIndex * 8 + 8).map(([globalBit, , meaning]) => {
      const bit = globalBit % 8;
      const active = (data[byteIndex] & (1 << bit)) !== 0;
      return { item: `bit${bit}`, content: meaning, value: active ? '1' : '0', active };
    })
  }));
}

function parseTerminalCapabilities(hex: string): DetailSection[] {
  const data = hexToBytes(hex);
  if (data.length !== 3) return [{ title: '9F33解析', rows: [{ item: '错误', content: 'Tag 9F33(终端性能)长度应为3字节。' }] }];
  const definitions = [
    ['第1字节: 卡片数据输入能力', ['手工键盘输入', '磁条输入', '接触式IC卡输入', '保留位', '保留位', '保留位', '保留位', '保留位']],
    ['第2字节: CVM能力', ['离线明文PIN验证', '联机加密PIN验证', '纸质签名验证', '离线加密PIN验证', '无需CVM', '保留位', '保留位', '保留位']],
    ['第3字节: 安全能力', ['SDA', 'DDA', '吞卡', '保留位', 'CDA', '保留位', '保留位', '保留位']]
  ] as const;
  return definitions.map(([title, meanings], byteIndex) => ({
    title,
    rows: meanings.map((meaning, index) => {
      const bit = 7 - index;
      const active = (data[byteIndex] & (1 << bit)) !== 0;
      return { item: `bit${bit}`, content: meaning, value: active ? '1' : '0', active };
    })
  }));
}

export function isViewableTag(tag: string): boolean {
  return ['82', '94', '95', '9F27', '8E', '8C', '8D', '9F38', '9F0D', '9F0E', '9F0F', '9F33'].includes(tag);
}

export function parseTagDetail(tag: string, value: string): DetailSection[] {
  if (tag === '82') return parseAip(value);
  if (tag === '94') return parseAfl(value);
  if (tag === '95' || ['9F0D', '9F0E', '9F0F'].includes(tag)) return parseTvrLike(tag, value);
  if (tag === '9F27') return parseCid(value);
  if (tag === '8E') return parseCvmList(value);
  if (['8C', '8D', '9F38'].includes(tag)) return parseDol(value);
  if (tag === '9F33') return parseTerminalCapabilities(value);
  return [{ title: `Tag ${tag} 数据解析`, rows: [{ item: tag, content: value }] }];
}
