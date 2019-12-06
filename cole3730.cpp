/*
  CPSC 3730 Cryptography
  COLE ANDERSON
  PROGRAM ASSIGNMENT: DES
        implement the DES algorithm to encrypt or decrypt a textfiles contents
  and overwrite
*/
// LIBRARIES/NAMESPACE
#include <algorithm>
#include <bitset>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using namespace std;
// Tables for encryption decryption
// Initial Permutation:
int initPerm[64] = {58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28,
                    20, 12, 4,  62, 54, 46, 38, 30, 22, 14, 6,  64, 56,
                    48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,
                    1,  59, 51, 43, 35, 27, 19, 11, 3,  61, 53, 45, 37,
                    29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7};
// Expansion D-Box: // ??
int expDbox[48] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
                   8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                   24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
//
// S-Box:
int sBox[8][4][16] = {
    {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
     0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
     4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
     15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13},
    {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
     3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
     0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
     13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9},
    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
     13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
     13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
     1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12},
    {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
     13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
     10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
     3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14},
    {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
     14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
     4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
     11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3},
    {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
     10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
     9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
     4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},
    {4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
     13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
     1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
     6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12},
    {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
     1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
     7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
     2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}};
// Permutation Function P:
int permfunc[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                    26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                    3,  9, 19, 13, 30, 6,  22, 11, 4,  25};
// Final Permutation:
int finalPerm[64] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55,
                     23, 63, 31, 38, 6,  46, 14, 54, 22, 62, 30, 37, 5,
                     45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60,
                     28, 35, 3,  43, 11, 51, 19, 59, 27, 34, 2,  42, 10,
                     50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};
// Parity Drop
int drop[56] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
                10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
                14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
// Shifter for bit shift
int shifterT[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
int compressionT[48] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
                        23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// Function Declarations

void input();
string encryption(string key, string fileTxt);
string decryption(string key, string fileTxt);
string permutation(string key, int *array, int b);
string shifter(string shiftD, int shiftT);
string xorF(string x, string y);
string read(string filename);
void write(string txt, string filename); // write to file
// MAIN FUNCTION
int main()
{
  input();
  return 0;
}
// FUNCTION FOR TAKING INPUT FROM USER
// AND FOR REDIRECTING TO OTHER FUNCTIONS
void input()
{
  int selection;
  string key;
  string fileName;
  string fileTxt;
  string inputED;
  string outputTxt;
  string outtoFile;
  int ftype;
  cout << "WARNING! THIS PROGRAM OVERWRITES THE SOURCE FILE WHEN ENCRYPTING "
          "AND DECRYPTING"
       << endl;
  cout << "Please choose from the following three options" << endl;
  cout << "Enter 1 for encryption" << endl;
  cout << "Enter 2 for decryption" << endl;
  cout << "Enter 0 to end program" << endl;
  cin >> selection;

  if (selection == 1)
  {

    // ENCRYPTION
    // cout << "Enter your KEY" << endl;
    // cin >> key;
    cout << "Enter fileName to encrypt" << endl;
    cin >> fileName;

    // read file
    fileTxt = read(fileName);

    // Check Length of File
    for (int g = 0; g < fileTxt.size() / 64; g++)
    {
      // infile = filecontent.substr(i*64, i*64 + 64)
      inputED = fileTxt.substr(g * 64, g * 64 + 64);
      outputTxt = encryption(key, inputED);
      // cout << outputTxt << endl;
      outtoFile.append(outputTxt);
    }

    // Write to File
    write(outtoFile, fileName);
    string expE =
        "1100000010110111101010001101000001011111001110101000001010011100";
    cout << "Result:   " << outtoFile << endl;
    cout << "Expected: " << expE << endl;
    selection++;

    // END ENCRYPT STAGE
  }
  else if (selection == 2)
  {
    // DECRYPTION
    // cout << "Enter your KEY" << endl;
    // cin >> key;
    cout << "Enter fileName to decrypt" << endl;
    cin >> fileName;
    fileTxt = read(fileName);
    write(outtoFile, fileName);

    // Decrypt
    for (int g = 0; g < fileTxt.size() / 64; g++)
    {
      inputED = fileTxt.substr(g * 64, g * 64 + 64);
      outputTxt = decryption(key, inputED);
      outtoFile.append(outputTxt);
    }
    // Write to File
    write(outtoFile, fileName);
    string expD =
        "0001001000110100010101101010101111001101000100110010010100110110";
    cout << "Result:   " << outtoFile << endl;
    cout << "Expected: " << expD << endl;
    selection++;

    // END DECRYPT STAGE
  }
  else
  {
    cout << "ENDING PROGRAM EXECUTION" << endl;
    exit(EXIT_FAILURE);
  }
}
// PRIMARY ENCRYPTION FUNCTION:
string encryption(string key, string line)
{
  // VARIABLE DECLARATIONS:
  string ciphertxt;
  string left, left2;              // LEFT SPLIT
  string right, right2;            // RIGHT SPLIT
  vector<string> roundK;           // ROUNDKEY
  string RoKey;                    // ROUNDKEY MANIPULATE
  string keyTogether, combination; // KEY WHEN ITS STITCHED BACK TOGETHER

  // line = "0001001000110100010101101010101111001101000100110010010100110110";
  key = "1010101010111011000010010001100000100111001101101100110011011101";
  // SHOULD END UP AS:
  // 1100000010110111101010001101000001011111001110101000001010011100

  /// 1)STEP 64-56 BIT KEY CONVERSION: __COMPLETE
  key = permutation(key, drop, 56);

  /// 2)STEP SPLIT KEY L R: __COMPLETE
  left = key.substr(0, 28);
  right = key.substr(28, 28);

  /// 3)STEP a)SHIFT/b)RE SPLICE TOGETHER/c)COMPRESSING
  for (int s = 0; s < 16; s++)
  {
    // a)
    left = shifter(left, shifterT[s]);
    right = shifter(right, shifterT[s]);
    // b)
    keyTogether = left + right;
    // c)
    RoKey = permutation(keyTogether, compressionT, 48);
    roundK.push_back(RoKey);
  }

  /// 4)STEP INITIAL PERMUTATION:
  line = permutation(line, initPerm, 64);

  // 5)STEP SPLIT LINE LR:
  left2 = line.substr(0, 32);
  right2 = line.substr(32, 32);

  /// 6)MAIN ALGORITHM(D-BOX,xorF,S-BOX,PERMUTATION)
  // 16 ROUNDS:
  for (int a = 0; a < 16; a++)
  {
    string rex = permutation(right2, expDbox, 48); //
    string xxor = xorF(roundK[a], rex);
    string operate = "";
    for (int z = 0; z < 8; z++)
    {
      int row = 2 * int(xxor[z * 6] - '0') + int(xxor[z * 6 + 5] - '0'); //#
      int col = 8 * int(xxor[z * 6 + 1] - '0') +
                4 * int(xxor[z * 6 + 2] - '0') +
                2 * int(xxor[z * 6 + 3] - '0') + int(xxor[z * 6 + 4] - '0');
      int fin = sBox[z][row][col];
      operate += char(fin / 8 + '0');
      fin = fin % 8;
      operate += char(fin / 4 + '0');
      fin = fin % 4;
      operate += char(fin / 2 + '0');
      fin = fin % 2;
      operate += char(fin + '0');
    }
    operate = permutation(operate, permfunc, 32);
    xxor = xorF(operate, left2);
    left2 = xxor;
    if (a != 15)
    {
      swap(left2, right2);
    }
    else
    {
      // do nothing
    }
  }
  /// 7)FINAL PERMUTATION
  combination = left2 + right2;
  ciphertxt = permutation(combination, finalPerm, 64);
  return ciphertxt;

  /// END ENCRYPTION
}
// PRIMARY DECRYPTION FUNCTION:
string decryption(string key, string line)
{
  // VARIABLE DECLARATIONS:
  string plaintext;
  string left, left2;              // LEFT SPLIT
  string right, right2;            // RIGHT SPLIT
  vector<string> roundK;           // ROUNDKEY
  string RoKey;                    // ROUNDKEY MANIPULATE
  string keyTogether, combination; // KEY WHEN ITS STITCHED BACK TOGETHER

  // as example
  // line = "1100000010110111101010001101000001011111001110101000001010011100";
  key = "1010101010111011000010010001100000100111001101101100110011011101";
  // SHOULD END UP AS:
  // 0001001000110100010101101010101111001101000100110010010100110110

  /// 1)STEP 64-56 BIT KEY CONVERSION: __COMPLETE
  key = permutation(key, drop, 56);

  /// 2)STEP SPLIT KEY L R: __COMPLETE
  left = key.substr(0, 28);
  right = key.substr(28, 28);

  /// 3)STEP a)SHIFT/b)RE SPLICE TOGETHER/c)COMPRESSING
  for (int s = 0; s < 16; s++)
  {
    // a)
    left = shifter(left, shifterT[s]);
    right = shifter(right, shifterT[s]);
    // b)
    keyTogether = left + right;
    // c)
    RoKey = permutation(keyTogether, compressionT, 48);
    roundK.push_back(RoKey);
  }
  // STEP 3.5 For Decrpytion Reverse The Key
  reverse(roundK.begin(), roundK.end());

  /// 4)STEP INITIAL PERMUTATION:
  line = permutation(line, initPerm, 64);

  // 5)STEP SPLIT LINE LR:
  left2 = line.substr(0, 32);
  right2 = line.substr(32, 32);

  /// 6)MAIN ALGORITHM(D-BOX,xorF,S-BOX,PERMUTATION)
  // 16 ROUNDS:
  for (int a = 0; a < 16; a++)
  {
    string rex = permutation(right2, expDbox, 48); //
    string xxor = xorF(roundK[a], rex);
    string operate = "";
    for (int z = 0; z < 8; z++)
    {
      int row = 2 * int(xxor[z * 6] - '0') + int(xxor[z * 6 + 5] - '0'); //#
      int col = 8 * int(xxor[z * 6 + 1] - '0') +
                4 * int(xxor[z * 6 + 2] - '0') +
                2 * int(xxor[z * 6 + 3] - '0') + int(xxor[z * 6 + 4] - '0');
      int fin = sBox[z][row][col];
      operate += char(fin / 8 + '0');
      fin = fin % 8;
      operate += char(fin / 4 + '0');
      fin = fin % 4;
      operate += char(fin / 2 + '0');
      fin = fin % 2;
      operate += char(fin + '0');
    }
    operate = permutation(operate, permfunc, 32);
    xxor = xorF(operate, left2);
    left2 = xxor;
    if (a != 15)
    {
      swap(left2, right2);
    }
    else
    {
      // do nothing
    }
  }
  /// 7)FINAL PERMUTATION
  combination = left2 + right2;
  plaintext = permutation(combination, finalPerm, 64);
  return plaintext;
}

// Reads in File
string read(string fileName)
{
  string ins = "";
  string in;
  ifstream inputF;
  inputF.open(fileName.c_str());
  while (getline(inputF, in))
  {
    ins.append(in);
  }
  inputF.close();
  // cout << "ins test:" << ins << endl;d
  return ins;
}
// Writes to File
void write(string files, string fileName)
{
  ofstream newF;
  newF.open(fileName.c_str());
  newF << files;
  // cout << "fileTxt:" << endl << files << endl;
}
// PERMUTATION FUNCTION:
string permutation(string plain, int *table, int b)
{
  string perm = "";
  for (int i = 0; i < b; i++)
  {
    perm += plain[table[i] - 1];
  }
  return perm;
}
// BIT SHIFTING FUNCTION:
string shifter(string shiftD, int shiftT)
{
  string sh = "";
  for (int s1 = 0; s1 < shiftT; s1++)
  {
    for (int s2 = 1; s2 < 28; s2++)
    {
      sh += shiftD[s2];
    }
    sh += shiftD[0];
    shiftD = sh;
    sh = "";
  }
  return shiftD;
}
// xorF FUNCTION:
string xorF(string x, string y)
{
  string r = "";
  for (int j = 0; j < x.size(); j++)
  {
    if (x[j] == y[j])
    {
      r += "0";
    }
    else
    {
      r += "1";
    }
  }
  return r;
}
