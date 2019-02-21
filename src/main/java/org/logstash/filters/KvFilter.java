package org.logstash.filters;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class KvFilter {
	private boolean noneBracket1 = false;
	private boolean noneBracket2 = false;
	private boolean noneBracket3 = false;

	public Map<String, Object> filter(String message) {
		Map<String, Object> result = new HashMap<>();
		for (int cursor = 0, msgLen = message.length(); cursor < msgLen;) {
			ScanResult keyResult = phase1(cursor, message);
			if (keyResult == null) {
				break;
			}
			if (keyResult.cursor >= msgLen) {
				break;
			}
			ScanResult valueResult = phase2(keyResult.cursor, message);
            if (valueResult.value.length() != 0) {
                if (result.containsKey(keyResult.value)) {
                    Object tmpVal = result.get(keyResult.value);
                    if (tmpVal instanceof List) {
                        @SuppressWarnings("unchecked")
                        List<String> tmpList = (List<String>) tmpVal;
                        tmpList.add(valueResult.value);
                    } else {
                        List<String> tmpList = new LinkedList<>();
                        tmpList.add(tmpVal.toString());
                        tmpList.add(valueResult.value);
                        result.put(keyResult.value, tmpList);
                    }
                } else {
                    result.put(keyResult.value, valueResult.value);	
                }
            }
			cursor = valueResult.cursor;
		}
		return result;
	}

	private static class ScanResult {
		public String value;
		public int cursor;

		public ScanResult(String value, int cursor) {
			this.value = value;
			this.cursor = cursor;
		}
	}

	private ScanResult phase1(int i, String message) {
		int state = 0, keyBegin = i, keyEnd = i, phase2Begin = i;
		for (int msgLen = message.length(); i < msgLen; ++i) {
			char c = message.charAt(i);
			switch (state) {
			case 0:
				if (c == ' ' || c == '=') {
					// stay
				} else if (c == '\\') {
					state = 1;
					keyBegin = i;
				} else {
					state = 3;
					keyBegin = i;
				}
				break;
			case 1:
				if (c == ' ') {
					state = 2;
				} else if (c == '=') {
					state = 5;
					keyEnd = i;
				} else if (c == '\\') {
					// stay
				} else {
					state = 3;
				}
				break;
			case 2:
				if (c == '\\') {
					state = 1;
				} else if (c == '=') {
					state = 5;
					keyEnd = i;
				} else if (c == ' ') {
					state = 4;
					keyEnd = i;
				} else {
					state = 3;
				}
				break;
			case 3:
				if (c == '\\') {
					state = 1;
				} else if (c == '=') {
					state = 5;
					keyEnd = i;
				} else if (c == ' ') {
					state = 4;
					keyEnd = i;
				}
				break;
			case 4:
				if (c == ' ') {

				} else if (c == '=') {
					state = 5;
				} else {
					state = 0;
					--i;
				}
				break;
			case 5:
				if (c != ' ') {
					phase2Begin = i;
					return new ScanResult(message.substring(keyBegin, keyEnd), phase2Begin);
				}
				break;
			}
		}
		return null;
	}

	private ScanResult phase2(int i, String message) {
		char c = message.charAt(i);
		if (c == '"') {
			ScanResult result = lookAhead(i, '"', message);
			if (result != null) {
				return result;
			}
		} else if (c == '\'') {
			ScanResult result = lookAhead(i, '\'', message);
			if (result != null) {
				return result;
			}
		} else if (c == '(' && !this.noneBracket1) {
			ScanResult result = lookAhead(i, ')', message);
			if (result != null) {
				return result;
			}
		} else if (c == '[' && !this.noneBracket2) {
			ScanResult result = lookAhead(i, ']', message);
			if (result != null) {
				return result;
			}
		} else if (c == '<' && !this.noneBracket3) {
			ScanResult result = lookAhead(i, '>', message);
			if (result != null) {
				return result;
			}
		}
		int state = 0, valueBegin = 0, valueEnd = 0;
		for (int msgLen = message.length(); i < msgLen; ++i) {
			c = message.charAt(i);
			switch (state) {
			case 0:
				if (c == '\\') {
					state = 1;
				} else {
					state = 3;
				}
				valueBegin = i;
				break;
			case 1:
				if (c == '\\') {
					// stay
				} else if (c == ' ') {
					state = 2;
				} else {
					state = 3;
				}
				break;
			case 2:
				if (c == '\\') {
					state = 1;
				} else if (c == ' ') {
					valueEnd = i;
					return new ScanResult(message.substring(valueBegin, valueEnd), valueEnd + 1);
				} else {
					state = 3;
				}
				break;
			case 3:
				if (c == '\\') {
					state = 1;
				} else if (c == ' ') {
					valueEnd = i;
					return new ScanResult(message.substring(valueBegin, valueEnd), valueEnd + 1);
				}
				break;
			}
		}
		valueEnd = i;
		return new ScanResult(message.substring(valueBegin, valueEnd), valueEnd + 1);
	}

	private ScanResult lookAhead(int i, char targetChar, String message) {
		for (int cursor = i + 1, msgLen = message.length(); cursor < msgLen; ++cursor) {
			if (message.charAt(cursor) == targetChar) {
				return new ScanResult(message.substring(i + 1, cursor), cursor + 1);
			}
		}
		if (targetChar == ')') {
			this.noneBracket1 = true;
		} else if (targetChar == ']') {
			this.noneBracket2 = true;
		} else if (targetChar == '>') {
			this.noneBracket3 = true;
		}
		return null;
	}
}
