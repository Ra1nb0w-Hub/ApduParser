export interface TlvItem {
  tag: string;
  name: string;
  value: string;
  length: number;
}

export interface ApduField {
  name: string;
  value: string;
  description: string;
}

export interface ApduInfo {
  rawHex: string;
  type: string;
  parameterDescription: string;
  sw: string;
  swDescription: string;
  tlvItems: TlvItem[];
  fields: ApduField[];
  error: string;
}

export interface ParseResult {
  request: ApduInfo;
  response: ApduInfo;
  requestDataDolTag: string;
  requestDataDolValue: string;
  requestDataDolWarning: string;
  error: string;
}

export interface ApduPairInput {
  request: string;
  response: string;
}
