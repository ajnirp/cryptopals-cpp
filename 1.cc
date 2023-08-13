// g++ 1.cc -std=c++17 -O3 && ./a.out

#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include <tuple>
#include <vector>

// As much as possible, we operate on vectors of bytes.
using vec = std::vector<char>;

// Converts a string to a vec. Does no encoding or decoding.
vec StringToVec(const std::string& s) {
	vec result(s.begin(), s.end());
	return result;
}

// Returns true if two vecs are elementwise equal.
bool IsEqualVec(const vec& u, const vec& v) {
	if (u.size() != v.size()) { return false; }
	for (int i = 0; i < u.size(); i++) {
		if (u[i] != v[i]) { return false; }
	}
	return true;
}

// Converts a vec to a string. Does no encoding or decoding.
std::string VecToString(const vec& v) {
	std::string s(v.begin(), v.end());
	return s;
}

// Converts a hex char to a byte. Does not validate input!
// Expects a char in range '0'..'9' or 'a'..'f'.
// Inverse of ByteToHexDigit().
char HexDigitToByte(char c) {
	return (c <= '9') ? (c - '0') : (c - 'a' + 10);
}

// Converts a byte to a hex char. Does not validate input!
// Expects a byte in range 0..15.
// Inverse of HexDigitToByte().
char ByteToHexDigit(char b) {
	if (b < 10) return b + '0';
	return b - 10 + 'a';
}

// Converts a byte to a base64 char. Does not validate input!
// Expects byte in range 0..63.
char ByteToBase64Digit(char b) {
	if (b < 26) { return b + 'A'; }
	if (b < 52) { return b - 26 + 'a'; }
	if (b < 62) { return b - 52 + '0'; }
	if (b == 62) return '+';
	return '/';
}

// Encodes a string of hex chars via base64. Outputs a base64 string.
// Does not validate input!
vec HexVecToBase64Vec(const vec& hex) {
	vec result;
	result.reserve(size_t(hex.size() * 2.0 / 3.0) + 1);

	// Algorithm: Process the input 3 hex chars at a time.
	// 3 hex chars = 12 binary digits = 2 b64 chars
	// If the input has length 1 or 2 modulo 3, then we pad the input as follows:
	// If input length is 1 mod 3 i.e. 4 leftover binary digits, add 2 binary 0s at the end to produce 1 b64 chars
	// If input length is 2 mod 3 i.e. 8 leftover binary digits, add 4 binary 0s at the end to produce 2 b64 chars
	for (int i = 0; i < hex.size() - (hex.size() % 3); i += 3) {
		char group[3];
		for (int j = 0; j < 3; j++) {
			group[j] = HexDigitToByte(hex[i+j]);
		}
		char sextet1 = (group[0] << 2) | (group[1] >> 2);
		char sextet2 = ((group[1] & 0b11) << 4) | group[2];
		result.push_back(ByteToBase64Digit(sextet1));
		result.push_back(ByteToBase64Digit(sextet2));
	}
	if (hex.size() % 3 == 1) {
		char sextet = HexDigitToByte(hex[hex.size()-1]) << 2;
		result.push_back(ByteToBase64Digit(sextet));
	} else if (hex.size() % 3 == 2) {
		char group[2];
		group[0] = HexDigitToByte(hex[hex.size()-2]);
		group[1] = HexDigitToByte(hex[hex.size()-1]);
		char sextet1 = (group[0] << 2) | (group[1] >> 2);
		char sextet2 = (group[1] & 0b11) << 4;
		result.push_back(ByteToBase64Digit(sextet1));
		result.push_back(ByteToBase64Digit(sextet2));
	}
	return result;
}

// Takes two equal-length hex strings and returns their bitwise XOR, also as a hex string.
// Does not validate inputs or input length!
vec FixedLengthXor(const vec& h1, const vec& h2) {
	vec result;
	result.reserve(h1.size());
	for (int i = 0; i < h1.size(); i++) {
		char d1 = HexDigitToByte(h1[i]);
		char d2 = HexDigitToByte(h2[i]);
		char c = ByteToHexDigit(d1 ^ d2);
		result.push_back(c);
	}
	return result;
}

// Accepts a byte in range 0..255 and a hex string s, and returns the fixed-length
// xor of s and the string obtained by converting the byte to 2 hex chars and repeating
// that until it matches the length of s.
// Expects s to have even length.
// Outputs the fixed-length xor in ASCII format.
vec SingleByteXor(const vec& s, char b) {
	vec result;
	result.reserve(s.size());
	for (int i = 0; i < s.size(); i += 2) {
		char d1 = HexDigitToByte(s[i]);
		char d2 = HexDigitToByte(s[i+1]);
		char half1 = d1 ^ (b >> 4);
		char half2 = d2 ^ (b & 0xf);
		result.push_back((half1 << 4) | half2);
	}
	return result;
}

// Scores a string by assigning +1 for each valid ASCII char and -1 for all others.
// Expects input s to have length < 2^32.
int32_t Score(const vec& s) {
	int32_t score = 0;
	for (const char c : s) {
		if (c == 32) { score += 3; }
		else if ((65 <= c && c <= 90) || (97 <= c && c <= 122)) { score += 2; }
		else if (33 <= c && c <= 127) { score++; }
		else { score -= 5; }
	}
	return score;
}

// Accepts a hex-encoded ciphertext string that has been encrypted by SingleByteXor()-ing it with an
// unknown byte key. Returns a 3-tuple of {plaintext, key, score}. The decryption relies
// on ranking the most likely key that was used to encrypt.
std::tuple<vec, char, int32_t> DecryptSingleByteXor(const vec& ciphertext) {
	int32_t max_score = 0;
	char most_likely_key = 0;
	for (int bb = 0; bb < 256; bb++) {
		char b = static_cast<char>(bb);
		const vec decrypted = SingleByteXor(ciphertext, b);
		if (Score(decrypted) > max_score) {
			max_score = Score(decrypted);
			most_likely_key = b;
		}
	}
	return {SingleByteXor(ciphertext, most_likely_key), most_likely_key, max_score};
}

int main() {
	std::vector<std::tuple<std::string, std::string>> testcases1 = {
		{"4d616e", "TWFu"}, // hex-encoding of "Man"
		{"4d61", "TWE"}, // hex-encoding of "Ma"
		{"4d", "TQ"}, // hex-encoding of "M"
		{
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
		 	"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	};
	if (std::all_of(testcases1.cbegin(), testcases1.cend(), [](auto tuple) {
		const vec input = StringToVec(std::get<0>(tuple));
		const vec output = StringToVec(std::get<1>(tuple));
		return IsEqualVec(HexVecToBase64Vec(input), output);
	})) {
		std::cout << "Base64 testcases passed." << std::endl;
	}

	std::vector<std::tuple<std::string, std::string, std::string>> testcases2 = {
		{
			"1c0111001f010100061a024b53535009181c",
			"686974207468652062756c6c277320657965",
			"746865206b696420646f6e277420706c6179",
		},
	};
	if (std::all_of(testcases2.cbegin(), testcases2.cend(), [](auto tuple) {
		const vec in0 = StringToVec(std::get<0>(tuple));
		const vec in1 = StringToVec(std::get<1>(tuple));
		const vec out = StringToVec(std::get<2>(tuple));
		return IsEqualVec(FixedLengthXor(in0, in1), out);
	})) {
		std::cout << "Fixed-length XOR testcases passed." << std::endl;
	}

	std::vector<std::string> testcases3 = {
		"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
	};
	for (const std::string& s : testcases3) {
		const vec in = StringToVec(s);
		std::tuple<vec, char, int32_t> decryption = DecryptSingleByteXor(in);
		const std::string plaintext = VecToString(std::get<0>(decryption));
		int32_t score = std::get<2>(decryption);
		std::cout << "Plaintext = " << plaintext << ". Key = " << std::get<1>(decryption) << ". Score = " << score << std::endl; 
	}

	std::ifstream ifs("single-character-xor.txt");
	if (ifs) {
		std::string line;
		std::string true_ciphertext_string;
		std::string true_plaintext;
		int32_t max_score = 0;
		while (!ifs.eof()) {
			std::getline(ifs, line);
			const vec ciphertext = StringToVec(line);
			std::tuple<vec, char, int32_t> decryption = DecryptSingleByteXor(ciphertext);
			int32_t score = std::get<2>(decryption);
			if (score > max_score) {
				max_score = score;
				true_ciphertext_string = line;
				true_plaintext = VecToString(std::get<0>(decryption));
			}
		}
		std::cout << "Plaintext = " << true_plaintext << ". Ciphertext = " << true_ciphertext_string << ". " << std::endl;
	}

	return 0;
}
