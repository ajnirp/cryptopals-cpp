// g++ 1.cc -std=c++17 -O3 && ./a.out

#include <algorithm>
#include <bitset>
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

char Base64DigitToByte(char d) {
	if ('A' <= d && d <= 'Z') { return d - 'A'; }
	if ('a' <= d && d <= 'z') { return d - 'a' + 26; }
	if ('0' <= d && d <= '9') { return d - '0' + 52; }
	if (d == '+') { return 62; }
	return 63;
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

// Converts a Base64-encoded string to a vec.
// Assumes s.size() is non-zero and a multiple of 4.
vec Base64StringToVec(const std::string& s) {
	// Processes a chunk of four Base64 digits starting at index i in s, converting them to
	// three ASCII bytes and appending them to the result vec.
	// Assumes that i+3 < s.size().
	auto ProcessChunkOf4 = [](const std::string& s, int i, vec& result) {
		char a, b, c, d;
		a = Base64DigitToByte(s[i]);
		b = Base64DigitToByte(s[i+1]);
		c = Base64DigitToByte(s[i+2]);
		d = Base64DigitToByte(s[i+3]);

		char A = (a << 2) | (b >> 4);
		char B = ((b & 0b1111) << 4) | (c >> 2);
		char C = ((c & 0b11) << 6) | d;

		result.push_back(A);
		result.push_back(B);
		result.push_back(C);
	};

	// Algorithm: Take 4 Base64 digits at a time. Convert them to 3 bytes.
	// If the input has one = at the end, we'll need to drop 2 binary 0s from the end while converting.
	// If it has two =s at the end, we'll need to drop 4 binary 0s from the end while converting.
	// Note that there are no other cases. An ASCII sequence will have a multiple-of-8 # of bits.
	// So the length in bits of an ASCII sequence is either 0, 2 or 4 mod 6.
	// See https://en.wikipedia.org/wiki/Base64#Examples.

	vec result;
	result.reserve(size_t((s.size() / 4) * 3));
	// Process all but the last 4 Base64 digits. We'll handle those separately.
	for (int i = 0; i < s.size() - 4; i += 4) {
		ProcessChunkOf4(s, i, result);
	}

	if (s[s.size()-1] != '=') {
		ProcessChunkOf4(s, s.size()-4, result);
	} else if (s[s.size()-2] != '=') {
		char a, b, c;
		int i = s.size()-4;
		a = Base64DigitToByte(s[i]);
		b = Base64DigitToByte(s[i+1]);
		c = Base64DigitToByte(s[i+2]);

		char A = (a << 2) | (b >> 4);
		char B = ((b & 0b1111) << 4) | (c >> 2);

		result.push_back(A);
		result.push_back(B);
	} else {
		int i = s.size()-4;
		char a, b;
		a = Base64DigitToByte(s[i]);
		b = Base64DigitToByte(s[i+1]);

		char A = (a << 2) | (b >> 4);

		result.push_back(A);
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

// Accepts a plaintext and key as ASCII strings and encrypts the former with the latter in
// repeating-key mode. Output is hex-encoded.
// See https://cryptopals.com/sets/1/challenges/5 for an example.
vec RepeatingKeyXor(const std::string& plaintext, const std::string& key) {
	vec result;
	result.reserve(plaintext.size() * 2); // 1 byte is 2 hex digits.
	int key_index = 0;
	for (char c : plaintext) {
		char byte = c ^ key[key_index];
		key_index = (key_index + 1) % key.size();
		result.push_back(ByteToHexDigit(byte >> 4));
		result.push_back(ByteToHexDigit(byte & 0xf));
	}
	return result;
}

// Returns the number of ones in a byte.
char CountOnes(char byte) {
	return std::bitset<8>(byte).count();
}

// Computes the number of differing bits between two vecs.
// Assumes that both vecs have the same size.
uint32_t NumDifferingBits(const vec& u, const vec& v) {
	uint32_t result = 0;
	for (int i = 0; i < u.size(); i++) {
		result += CountOnes(u[i] ^ v[i]);
	}
	return result;
}

// Read the contents of `filename` and return them as a vector of byte sequences,
// skipping over any newline characters.
std::vector<vec> ReadChallenge4Input(const std::string& filename) {
	std::ifstream file(filename);
	std::vector<vec> result;
	if (file) {
		std::string line;
		while (!file.eof()) {
			std::getline(file, line);
			result.push_back(StringToVec(line));
		}
	}
	return result;
}

// Read the contents of `filename` and return them as a string, skipping over any
// newline characters.
std::string ReadChallenge6Input(const std::string& filename) {
	std::ifstream file(filename);
	std::string result;
	if (file) {
		std::string line;
		while (!file.eof()) {
			std::getline(file, line);
			result.append(line);
		}
	}
	return result;
}

int main() {
	// Challenge 1
	{
		std::vector<std::tuple<std::string, std::string>> testcases = {
			{"4d616e", "TWFu"}, // hex-encoding of "Man"
			{"4d61", "TWE"}, // hex-encoding of "Ma"
			{"4d", "TQ"}, // hex-encoding of "M"
			{
				"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			 	"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
			},
		};
		if (std::all_of(testcases.cbegin(), testcases.cend(), [](auto tuple) {
			const vec input = StringToVec(std::get<0>(tuple));
			const vec output = StringToVec(std::get<1>(tuple));
			return IsEqualVec(HexVecToBase64Vec(input), output);
		})) {
			std::cout << "Base64 testcases passed." << std::endl;
		}
	}

	// Challenge 2
	{
		const std::vector<std::tuple<std::string, std::string, std::string>> testcases = {
			{
				"1c0111001f010100061a024b53535009181c",
				"686974207468652062756c6c277320657965",
				"746865206b696420646f6e277420706c6179",
			},
		};
		if (std::all_of(testcases.cbegin(), testcases.cend(), [](auto tuple) {
			const vec in0 = StringToVec(std::get<0>(tuple));
			const vec in1 = StringToVec(std::get<1>(tuple));
			const vec out = StringToVec(std::get<2>(tuple));
			return IsEqualVec(FixedLengthXor(in0, in1), out);
		})) {
			std::cout << "Fixed-length XOR testcases passed." << std::endl;
		}
	}

	// Challenge 3
	{
		const std::vector<std::string> testcases = {
			"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
		};
		for (const std::string& s : testcases) {
			const vec in = StringToVec(s);
			std::tuple<vec, char, int32_t> decryption = DecryptSingleByteXor(in);
			const std::string plaintext = VecToString(std::get<0>(decryption));
			int32_t score = std::get<2>(decryption);
			std::cout << "Plaintext = " << plaintext << ". Key = " << std::get<1>(decryption) << ". Score = " << score << std::endl;
		}
	}

	// Challenge 4
	{
		const std::vector<vec> inputs = ReadChallenge4Input("single-character-xor.txt");
		std::string true_ciphertext_string;
		std::string true_plaintext;
		int32_t max_score = 0;
		for (const vec& ciphertext : inputs) {
			std::tuple<vec, char, int32_t> decryption = DecryptSingleByteXor(ciphertext);
			int32_t score = std::get<2>(decryption);
			if (score > max_score) {
				max_score = score;
				true_ciphertext_string = VecToString(ciphertext);
				true_plaintext = VecToString(std::get<0>(decryption));
			}
		}
		std::cout << "Plaintext = " << true_plaintext << ". Ciphertext = " << true_ciphertext_string << ". " << std::endl;
	}

	// Challenge 5
	{
		const std::string testcase = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
		const std::string expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
		if (VecToString(RepeatingKeyXor(testcase, "ICE")) == expected) {
			std::cout << "Repeating-key XOR testcase passed." << std::endl;
		}
	}

	// Challenge 6
	{
		const vec in0 = StringToVec("this is a test");
		const vec in1 = StringToVec("wokka wokka!!!");
		if (NumDifferingBits(in0, in1) == 37) {
			std::cout << "Hamming distance testcase passed." << std::endl;
		}

		// Read the Base64-encoded file into a single string.
		std::cout << ReadChallenge6Input("repeating-key-xor.txt") << std::endl;
	}
	{
		const std::vector<std::tuple<std::string, std::string>> testcases = {
			{"TWFu", "Man"},
			{"TWE=", "Ma"},
			{"TQ==", "M"},
		};
		if (std::all_of(testcases.cbegin(), testcases.cend(), [](auto tuple) {
			const std::string& in = std::get<0>(tuple);
			const std::string& out = std::get<1>(tuple);
			return VecToString(Base64StringToVec(in)) == out;
		})) {
			std::cout << "Base64 to ASCII testcases passed" << std::endl;
		}
	}

	return 0;
}
