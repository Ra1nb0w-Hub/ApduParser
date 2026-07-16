import type { ApduInfo, ParseResult, TlvItem } from './types';

const tagNames: Record<string, string> = {
  '4F': '应用标识符', '50': '应用标签', '57': '二磁道等效数据', '5A': '应用主账号',
  '5F20': '持卡人姓名', '5F24': '应用失效日期', '5F25': '应用生效日期', '5F28': '发卡行国家代码',
  '5F2A': '交易货币代码', '5F2D': '首选语言', '5F34': '应用PAN序列号', '5F36': '交易货币指数',
  '61': '应用模板', '6F': '文件控制信息模板', '70': '读记录响应报文模板', '77': '响应报文模板格式2',
  '80': '响应报文模板格式1', '82': '应用交互特征', '84': '专用文件名称', '87': '应用优先级指示器',
  '88': '短文件标识符', '8A': '授权响应码', '8C': '卡片风险管理数据对象列表1', '8D': '卡片风险管理数据对象列表2',
  '8E': '持卡人验证方法列表', '8F': '认证中心公钥索引', '90': '发卡行公钥证书', '91': '发卡行认证数据',
  '92': '发卡行公钥余数', '93': '签名的静态应用数据', '94': '应用文件定位器', '95': '终端验证结果',
  '9A': '交易日期', '9B': '交易状态信息', '9C': '交易类型', '9F02': '授权金额', '9F03': '其他金额',
  '9F06': '终端应用标识符', '9F07': '应用用途控制', '9F08': '应用版本号', '9F0D': '发卡行行为代码-缺省',
  '9F0E': '发卡行行为代码-拒绝', '9F0F': '发卡行行为代码-联机', '9F10': '发卡行应用数据', '9F11': '发卡行代码表索引',
  '9F12': '应用首选名称', '9F17': 'PIN重试次数', '9F1A': '终端国家代码', '9F1F': '磁条1自定义数据',
  '9F26': '应用密文', '9F27': '密文信息数据', '9F32': '发卡行公钥指数', '9F33': '终端能力',
  '9F34': '持卡人验证方法结果', '9F35': '终端类型', '9F36': '应用交易计数器', '9F37': '不可预知数',
  '9F38': '处理选项数据对象列表', '9F42': '应用货币码', '9F46': 'IC卡公钥证书', '9F47': 'IC卡公钥指数',
  '9F48': 'IC卡公钥余项', '9F49': '动态数据认证数据对象列表', '9F4A': '静态数据认证标签列表',
  '9F4B': '签名动态应用数据', '9F4C': 'ICC动态数', '9F4E': '商户名称', '9F66': '终端交易属性',
  '9F6C': '卡片交易限定符', 'A5': '文件控制信息专有模板', 'BF0C': 'FCI发卡行自定义数据'
};

const swDescriptions: Record<string, string> = {
  '9000': '成功', '6200': '警告：状态未改变', '6281': '返回数据可能损坏', '6282': '文件或记录到达结束位置',
  '6283': '选择的文件无效', '6284': 'FCI格式与规范不一致', '6300': '警告：状态已改变', '6700': '长度错误',
  '6800': 'CLA功能不支持', '6881': '不支持逻辑通道', '6882': '不支持安全报文', '6900': '命令不允许',
  '6982': '安全状态不满足', '6983': '认证方法锁定', '6984': '引用数据无效', '6985': '使用条件不满足',
  '6986': '命令不允许（无当前EF）', '6A80': '数据字段参数错误', '6A81': '功能不支持', '6A82': '文件或应用不存在',
  '6A83': '记录不存在', '6A84': '文件空间不足', '6A86': 'P1/P2参数不正确', '6A87': 'Lc与P1/P2不一致',
  '6D00': 'INS不支持', '6E00': 'CLA不支持', '6F00': '未知错误'
};

export function tagName(tag: string): string {
  return tagNames[tag] ?? '未知Tag';
}

function swDescription(sw: string): string {
  return swDescriptions[sw] ?? '未知状态字';
}

function emptyInfo(rawHex = ''): ApduInfo {
  return { rawHex, type: '', parameterDescription: '', sw: '', swDescription: '', tlvItems: [], fields: [], error: '' };
}

function normalizeHex(input: string): string {
  const hex = input.replace(/\s+/g, '').toUpperCase();
  if (!hex) throw new Error('不能为空。');
  if (!/^[0-9A-F]+$/.test(hex)) throw new Error('只能输入HEX字符和空白分隔符。');
  if (hex.length % 2 !== 0) throw new Error('HEX字符数量必须为偶数。');
  return hex;
}

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  return bytes;
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join('');
}

function instructionName(ins: number): string {
  const names: Record<number, string> = {
    0xA4: 'SELECT(选择)', 0xA8: 'GET PROCESSING OPTIONS(获取处理选项)', 0xB2: 'READ RECORD(读取记录)',
    0xAE: 'GENERATE AC(生成应用密文)', 0xCA: 'GET DATA(读取数据)', 0x84: 'GET CHALLENGE(获取挑战数)',
    0x20: 'VERIFY(验证)'
  };
  return names[ins] ?? '未知指令';
}

function p1Description(ins: number, p1: number): string {
  if (ins === 0xA4) return ({ 0x00: '通过文件标识符选择', 0x01: '选择子DF', 0x02: '选择EF', 0x03: '选择父DF', 0x04: '通过名称选择' } as Record<number, string>)[p1] ?? 'SELECT P1含义未知';
  if (ins === 0xB2) return '记录号';
  if (ins === 0xCA) return 'Tag高字节';
  if (ins === 0xAE) {
    const cryptogramType = p1 & 0xC0;
    let text = cryptogramType === 0x00 ? '请求AAC(应用授权密文)' : cryptogramType === 0x40 ? '请求TC(交易证书)' : cryptogramType === 0x80 ? '请求ARQC(授权请求密文)' : '预留密文类型';
    if ((p1 & 0x10) === 0x10) text += '，请求CDA(复合动态数据认证)';
    return text;
  }
  return '默认值';
}

function p2Description(ins: number, p2: number): string {
  if (ins === 0xA4) return ({ 0x00: '第一个或仅有一个', 0x02: '下一个' } as Record<number, string>)[p2 & 0x03] ?? 'SELECT P2含义未知';
  if (ins === 0xB2) return `SFI=${p2 >> 3}`;
  if (ins === 0xCA) return 'Tag低字节';
  return '默认值';
}

function parseRequest(data: number[], rawHex: string): ApduInfo {
  const info = emptyInfo(rawHex);
  if (data.length < 4) {
    info.error = '请求APDU至少需要包含CLA、INS、P1、P2。';
    return info;
  }

  const [cla, ins, p1, p2] = data;
  const claHex = bytesToHex([cla]);
  const insHex = bytesToHex([ins]);
  const p1Hex = bytesToHex([p1]);
  const p2Hex = bytesToHex([p2]);
  info.type = instructionName(ins);
  const p1Text = p1Description(ins, p1);
  const p2Text = p2Description(ins, p2);
  info.parameterDescription = `CLA=${claHex}，INS=${insHex}（${info.type}），P1=${p1Hex}（${p1Text}），P2=${p2Hex}（${p2Text}）`;
  info.fields = [
    { name: 'CLA', value: claHex, description: '命令类别' },
    { name: 'INS', value: insHex, description: info.type },
    { name: 'P1', value: p1Hex, description: p1Text },
    { name: 'P2', value: p2Hex, description: p2Text }
  ];

  if (data.length === 4) return info;
  const lc = data[4];
  const lcHex = bytesToHex([lc]);
  if (data.length === 5) {
    info.parameterDescription += `，Le=${lcHex}`;
    info.fields.push({ name: 'Le', value: lcHex, description: '期望返回数据长度' });
    return info;
  }

  if (data.length < 5 + lc) {
    info.error = 'Lc长度超过请求APDU剩余数据长度。';
    return info;
  }

  const commandData = data.slice(5, 5 + lc);
  info.parameterDescription += `，Lc=${lcHex}，数据长度=${commandData.length}字节`;
  info.fields.push({ name: 'Lc', value: lcHex, description: '命令数据长度' });
  info.fields.push({ name: 'DATA', value: bytesToHex(commandData), description: '命令数据' });

  if (data.length === 5 + lc + 1) {
    const leHex = bytesToHex([data[data.length - 1]]);
    info.parameterDescription += `，Le=${leHex}`;
    info.fields.push({ name: 'Le', value: leHex, description: '期望返回数据长度' });
  } else if (data.length !== 5 + lc) {
    info.error = '请求APDU长度与Lc/Le不匹配。';
    return info;
  }

  if (commandData.length > 0) {
    info.tlvItems = [{ tag: 'DATA', name: '命令数据', value: bytesToHex(commandData), length: commandData.length }];
  }
  return info;
}

function parseTlvList(data: number[]): TlvItem[] {
  const items: TlvItem[] = [];
  let offset = 0;
  while (offset < data.length) {
    const tagStart = offset++;
    if ((data[tagStart] & 0x1F) === 0x1F) {
      do {
        if (offset >= data.length) throw new Error('EMV Tag不完整。');
      } while ((data[offset++] & 0x80) === 0x80);
    }
    const tagBytes = data.slice(tagStart, offset);
    const tag = bytesToHex(tagBytes);
    if (offset >= data.length) throw new Error(`Tag ${tag} 缺少长度字段。`);

    let length = data[offset++];
    if ((length & 0x80) !== 0) {
      const lengthBytes = length & 0x7F;
      if (lengthBytes === 0 || lengthBytes > 3) throw new Error(`Tag ${tag} 长度字段不支持。`);
      if (offset + lengthBytes > data.length) throw new Error(`Tag ${tag} 长度字段不完整。`);
      length = 0;
      for (let i = 0; i < lengthBytes; ++i) length = (length << 8) | data[offset++];
    }
    if (offset + length > data.length) throw new Error(`Tag ${tag} 的值长度超过剩余数据。`);

    const value = data.slice(offset, offset + length);
    items.push({ tag, name: tagName(tag), value: bytesToHex(value), length });
    if ((tagBytes[0] & 0x20) === 0x20 && length > 0) items.push(...parseTlvList(value));
    offset += length;
  }
  return items;
}

function expandTemplate80(item: TlvItem, requestIns: number, requestP1: number): TlvItem[] {
  if (requestIns === 0xA8) return expandGpoTemplate80(item);
  if (requestIns === 0xAE) return expandGacTemplate80(item, requestP1);
  return [item];
}

function expandGpoTemplate80(item: TlvItem): TlvItem[] {
  const value = hexToBytes(item.value);
  if (value.length < 2) return [item];
  const items: TlvItem[] = [{ tag: '82', name: tagName('82'), value: bytesToHex(value.slice(0, 2)), length: 2 }];
  const afl = value.slice(2);
  if (afl.length > 0) items.push({ tag: '94', name: tagName('94'), value: bytesToHex(afl), length: afl.length });
  return items;
}

function expandGacTemplate80(item: TlvItem, requestP1: number): TlvItem[] {
  const value = hexToBytes(item.value);
  if (value.length < 11) return [item];
  const items: TlvItem[] = [
    { tag: '9F27', name: tagName('9F27'), value: bytesToHex(value.slice(0, 1)), length: 1 },
    { tag: '9F36', name: tagName('9F36'), value: bytesToHex(value.slice(1, 3)), length: 2 },
    { tag: '9F26', name: tagName('9F26'), value: bytesToHex(value.slice(3, 11)), length: 8 }
  ];
  const rest = value.slice(11);
  if (rest.length > 0) {
    const cdaRequested = (requestP1 & 0x10) === 0x10;
    items.push({ tag: cdaRequested ? '9F4B' : '9F10', name: tagName(cdaRequested ? '9F4B' : '9F10'), value: bytesToHex(rest), length: rest.length });
  }
  return items;
}

function parseResponse(data: number[], rawHex: string, requestIns: number, requestP1: number): ApduInfo {
  const info = emptyInfo(rawHex);
  if (data.length < 2) {
    info.error = '响应APDU至少需要包含SW1、SW2。';
    return info;
  }
  const responseData = data.slice(0, -2);
  info.sw = bytesToHex(data.slice(-2));
  info.swDescription = swDescription(info.sw);
  if (responseData.length === 0) return info;

  try {
    info.tlvItems = parseTlvList(responseData);
    if (info.tlvItems.length === 1 && info.tlvItems[0].tag === '80') info.tlvItems = expandTemplate80(info.tlvItems[0], requestIns, requestP1);
  } catch (error) {
    if (responseData[0] === 0x80) {
      let value = responseData;
      if (requestIns === 0xA8) {
        const withoutTemplate = responseData.slice(1);
        if (withoutTemplate.length >= 2 && (withoutTemplate.length - 2) % 4 === 0) value = withoutTemplate;
      }
      info.tlvItems = expandTemplate80({ tag: '80', name: '响应数据（非TLV格式）', value: bytesToHex(value), length: value.length }, requestIns, requestP1);
    } else {
      info.error = error instanceof Error ? error.message : 'TLV解析失败。';
    }
  }
  return info;
}

export function validateCommandApdu(requestHex: string): string {
  try {
    const normalizedRequest = normalizeHex(requestHex);
    const request = parseRequest(hexToBytes(normalizedRequest), normalizedRequest);
    return request.error;
  } catch (error) {
    return error instanceof Error ? error.message : '请求APDU校验失败。';
  }
}

export function parseApdu(requestHex: string, responseHex: string): ParseResult {
  const result: ParseResult = { request: emptyInfo(), response: emptyInfo(), requestDataDolTag: '', requestDataDolValue: '', requestDataDolWarning: '', error: '' };
  try {
    const normalizedRequest = normalizeHex(requestHex);
    const normalizedResponse = normalizeHex(responseHex);
    const requestData = hexToBytes(normalizedRequest);
    result.request = parseRequest(requestData, normalizedRequest);
    if (result.request.error) {
      result.error = `APDU请求数据错误：${result.request.error}`;
      return result;
    }
    const requestIns = requestData.length > 1 ? requestData[1] : 0;
    const requestP1 = requestData.length > 2 ? requestData[2] : 0;
    result.response = parseResponse(hexToBytes(normalizedResponse), normalizedResponse, requestIns, requestP1);
    if (result.response.error) result.error = `APDU响应数据错误：${result.response.error}`;
  } catch (error) {
    result.error = error instanceof Error ? error.message : '解析失败。';
  }
  return result;
}

export function cryptogramTypeText(cidHex: string): string {
  const bytes = hexToBytes(cidHex);
  if (bytes.length !== 1) return '';
  const type = (bytes[0] >> 6) & 0x03;
  if (type === 0x00) return 'AAC(脱机拒绝)';
  if (type === 0x01) return 'TC(脱机批准)';
  if (type === 0x02) return 'ARQC(联机请求)';
  return '预留密文类型';
}

export function getFieldValue(result: ParseResult, name: string): string {
  return result.request.fields.find((field) => field.name === name)?.value ?? '';
}
