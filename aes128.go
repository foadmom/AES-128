package aes128

// ==================================================================
// references:
// https://zerofruit.medium.com/what-is-aes-step-by-step-fcb2ba41bb20
// this is the 128 bit implementation
// ==================================================================

const MATRIX_SIZE = 4;
const NO_OF_ROUNDS = 10;

type Workspace struct {
	processingRound int;		// no of rounds in the encryption processing
	sBox			[]byte;
	mdxMatrix		[][]byte;
	Rcon			[][]byte;
	cipherKey 		[]byte;		// the original supplied cipherkey
	cipherKeyBlock 	[][]byte;		// the original supplied cipherkey
	currentKeyBlock [][]byte;	// the keyBlock being used in the current round
	keyBlockList	[][][]byte; // an array of blockKey used for generated subKeys
	dataPacket   	[]byte;		// the original plain text to be ecrypted
	workingBlock 	[][]byte;	// the plainText arranged in matrix for processing
	//
	inv_sBox		[]byte;
	inv_mdxMatrix   [][]byte;

};

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// Initialise the Workspace struct and set the contants
// ==================================================================
func Initialise () *Workspace {

	// ====================================================
	var Rcon [][]byte = [][]byte {
		{0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	 };

	//        0     1      2    3     4     5     6     7     8     9     a     b     c     d     e     f
	var S_box []byte = []byte {
/* 0 */		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
/* 1 */		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
/* 2 */		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
/* 3 */		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
/* 4 */		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
/* 5 */		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
/* 6 */		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
/* 7 */		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
/* 8 */		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
/* 9 */		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
/* a */		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
/* b */		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
/* c */		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
/* d */		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
/* e */		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
/* f */		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

	//        0     1      2    3     4     5     6     7     8     9     a     b     c     d     e     f
	var rS_box []byte = []byte {
/* 0 */		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
/* 1 */		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
/* 2 */		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
/* 3 */		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
/* 4 */		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
/* 5 */		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
/* 6 */		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
/* 7 */		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
/* 8 */		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
/* 9 */		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
/* a */		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
/* b */		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
/* c */		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
/* d */		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
/* e */		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
/* f */		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};
	  

	// MDS matrix (Maximum Distance Separable) 
	var MDX_matrix [][]byte = [][]byte 	{ 
		{2,3,1,1},
		{1,2,3,1},
		{1,1,2,3},
		{3,1,1,2},
    };
	// MDS matrix (Maximum Distance Separable) 
	var inverse_MDX_matrix [][]byte = [][]byte 	{ 
		{0x0e, 0x0b, 0x0d, 0x09},
		{0x09, 0x0e, 0x0b, 0x0d},
		{0x0d, 0x09, 0x0e, 0x0b},
		{0x0b, 0x0d, 0x09, 0x0e},
    };

										
	// ====================================================

	var _ws Workspace;
	_ws.sBox = S_box;
	_ws.mdxMatrix = MDX_matrix;
	_ws.Rcon = Rcon;

	_ws.inv_sBox = rS_box;
	_ws.inv_mdxMatrix = inverse_MDX_matrix;

	return &_ws;
}

// ==================================================================
// 
// ==================================================================
func SetCipherKey (ws *Workspace, cipherKey []byte) error {
	ws.cipherKey = cipherKey;
	_err := setCipherBlock (ws);
	generateSubKeys (ws);

	return _err;
}

// ==================================================================
// 
// ==================================================================
func setCipherBlock (ws *Workspace) error {
	var _keyBlock [][]byte = makeNewBlock (MATRIX_SIZE, MATRIX_SIZE);
	for _row := range _keyBlock {
		_keyBlock [_row][0] = ws.cipherKey [_row];
		_keyBlock [_row][1] = ws.cipherKey [(_row)+MATRIX_SIZE];
		_keyBlock [_row][2] = ws.cipherKey [(_row)+MATRIX_SIZE*2];
		_keyBlock [_row][3] = ws.cipherKey [(_row)+MATRIX_SIZE*3];
	}
	// each round has a keyblock, but the original cipherKey
	ws.cipherKeyBlock = _keyBlock;
	return nil;
}

// ==================================================================
// this is the process of creating subkeys from the original cipher
// ==================================================================
func generateSubKeys (ws *Workspace) error {
	ws.keyBlockList = make ([][][]byte, NO_OF_ROUNDS);
	// round 0 is where original cipher key is used, so it is not 
	// considered a round
	for _round := 0; _round<NO_OF_ROUNDS; _round++ {
		if (_round == 0) {
			ws.keyBlockList [_round] = generateAKeyFromPreviousKey (ws, ws.cipherKeyBlock, _round);
		} else {	
			ws.keyBlockList [_round] = generateAKeyFromPreviousKey (ws, ws.keyBlockList[_round-1], _round);
		}
	}
	return nil;
}

// ==================================================================
// ==================================================================
// col 0 fo the new subkey is treated differently than the rest.
// 
//     previous                   new key
// 0 | 1 |  2 |  3 |           |  |  |  |
// 4 | 5 |  6 |  7 |           |  |  |  |
// 8 | 9 |  a |  b |           |  |  |  |
// c | d |  e |  f |           |  |  |  |
//
//  take column[3] and rotate up by 1
// 0 | 1 |  2 |  3 |           | 7 |   |  |  |
// 4 | 5 |  6 |  7 |           | b |   |  |  |
// 8 | 9 |  a |  b |           | f |   |  |  |
// c | d |  e |  f |           | 3 |   |  |  |
//
// convert the new column by using SBox to subs the values 
// 0 | 1 |  2 |  3 |           | c5 |  |  |  |
// 4 | 5 |  6 |  7 |           | 2b |  |  |  |
// 8 | 9 |  a |  b |           | 76 |  |  |  |
// c | d |  e |  f |           | 7b |  |  |  |
// 
// now XOR the new column with previousBlock col[0]
// then xor with Rcon col=round-1
// columns 1,2 and 3 are processed simply by XOR of :
//     previous column of the new key and
//     corresponding column of previous block
// ==================================================================
func generateAKeyFromPreviousKey (ws *Workspace, previousBlock [][]byte, round int) [][]byte {
	var _subKeyBlock [][]byte = makeNewBlock (MATRIX_SIZE, MATRIX_SIZE);

	// first column is taken from the last column of the pervious keyBlock then
	// rotated up by one byte, then substituted using the S_box
	_subKeyBlock [0][0] = (ws.sBox [previousBlock [1][3]]) ^ previousBlock [0][0] ^ ws.Rcon [0][round];
	_subKeyBlock [1][0] = (ws.sBox [previousBlock [2][3]]) ^ previousBlock [1][0] ^ ws.Rcon [1][round];
	_subKeyBlock [2][0] = (ws.sBox [previousBlock [3][3]]) ^ previousBlock [2][0] ^ ws.Rcon [2][round];
	_subKeyBlock [3][0] = (ws.sBox [previousBlock [0][3]]) ^ previousBlock [3][0] ^ ws.Rcon [3][round];	
	// columns 1-3 are simpler
	for _col:=1; _col<MATRIX_SIZE; _col++ {
		_subKeyBlock [0][_col] = previousBlock [0][_col] ^ _subKeyBlock [0][_col-1];
		_subKeyBlock [1][_col] = previousBlock [1][_col] ^ _subKeyBlock [1][_col-1];
		_subKeyBlock [2][_col] = previousBlock [2][_col] ^ _subKeyBlock [2][_col-1];
		_subKeyBlock [3][_col] = previousBlock [3][_col] ^ _subKeyBlock [3][_col-1];
	}

	return _subKeyBlock;
}

// ==================================================================
// ==================================================================
// ==================================================================
func SetDataBlock (ws *Workspace, data []byte) {
	ws.dataPacket = data;
	ws.workingBlock =  blockFromArray (data);
}

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func roundKey (ws *Workspace) error {
	for _row := range ws.workingBlock {
		for _col := range ws.workingBlock [_row] {
			ws.workingBlock [_row][_col] = ws.workingBlock [_row][_col] ^ ws.currentKeyBlock [_row][_col];
		}
	}
	return nil;
}

// ==================================================================
// ==================================================================
// ==================================================================
// this func subs each element of the block with matching element 
// from S_box. 
// eg if the element is 0x61 it is substituted with S_box[0x61]
// ==================================================================
func substitudeBytes (wb [][]byte, sBox []byte) ([][]byte, error) {
	for _row := range wb {
		for _col := range wb [_row] {
			wb [_row][_col] = sBox [wb [_row][_col]];
		}
	}

	return wb, nil;
}

// ==================================================================
// ==================================================================
// ==================================================================
// given a row perform 1 circular left rotate on the bytes in the row.
// eg row 1 2 3 4 becomes 2 3 4 1
// ==================================================================
func shift_l1 (row []byte) []byte {
	var _temp byte = row [0];
	row [0] = row [1]; 
	row [1] = row [2]; 
	row [2] = row [3]; 
	row [3] = _temp;
	return row;
}

// ==================================================================
// given a row perform 2 circular left rotate on the bytes in the row.
// eg row 1 2 3 4 becomes 3 4 1 2
// ==================================================================
func shift_l2 (block []byte) []byte {
	var _temp1 byte = block [0];
	var _temp2 byte = block [1];
	block [0] = block [2]; 
	block [1] = block [3]; 
	block [2] = _temp1;
	block [3] = _temp2;
	return block;
}


// ==================================================================
// given a row perform 3 circular left rotate on the bytes in the row.
// this is equivalent to a single right rotate
// eg row 1 2 3 4 becomes 4 1 2 3
// ==================================================================
func shift_l3 (block []byte) []byte {
	var _temp byte = block [3];
	block [3] = block [2]; 
	block [2] = block [1]; 
	block [1] = block [0]; 
	block [0] = _temp;
	return block;
}

// ==================================================================
// shiftRows takes a full block and performs:
// single left rotate on row [1], double left rotate on row [2]
// triple left rotate on [3]. row [0] is untouched
// ==================================================================
// func shiftRows (ws *Workspace) error {
// 	ws.workingBlock[1] = shift_l1 (ws.workingBlock[1]);
// 	ws.workingBlock[2] = shift_l2 (ws.workingBlock[2]);
// 	ws.workingBlock[3] = shift_l3 (ws.workingBlock[3]);

// 	return nil;
// }
func shiftRows (wb [][]byte) ([][]byte,error) {
	wb[1] = shift_l1 (wb[1]);
	wb[2] = shift_l2 (wb[2]);
	wb[3] = shift_l3 (wb[3]);

	return wb, nil;
}


// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// this envolves matrix-vector multiplication of the block
// with the mdx-matrix. 
// see explanation in mixElement function for further details
// ==================================================================
func MixColumns (ws *Workspace) ([][]byte, error) {
	return mixColumns (ws.workingBlock, ws.mdxMatrix);
}



// ==================================================================
// this envolves matrix-vector multiplication of the block
// with the mdx-matrix. 
// see explanation in mixElement function for further details
// ==================================================================
func mixColumns (wb [][]byte, matrix [][]byte) ([][]byte, error) {
	var _mixedBlock [][]byte = makeNewBlock (MATRIX_SIZE,MATRIX_SIZE);
	for _row := range wb {
		for _col := range wb [_row] {
			_mixedBlock [_row][_col] = mixElement (wb, matrix, _row, _col);
		}
	}
	wb = _mixedBlock;
	return wb, nil;
}


// ==================================================================
// var multiplyFuncs []func(a byte) (x byte) = []func(a byte) (x byte) {
// 	GF_invalidMultiply,
// 	GF_multiply1,
// 	GF_multiply2,
// 	GF_multiply3,
// };
// ==================================================================
// this function performs the mix for one element in block[row][column]
// this is done by matrix multiplication.
// all the elements of the block [column] are multiplied by all the 
//		elements of corresponding mdxMatrix [row].
// eg for block [2][3] 
// 		block [0][3] * mdxMatrix [2][0]
// 		block [1][3] * mdxMatrix [2][1]
// 		block [2][3] * mdxMatrix [2][2]
// 		block [3][3] * mdxMatrix [2][3]
// ==================================================================
func mixElement (block [][]byte, mdxMatrix [][]byte, row, column int) byte {
	var _res byte;
	for i := range block {
		var _element byte;
//		_func := multiplyFuncs [mdxMatrix [row][i]];
//		_element = _func (block [i][column]);
		_element = multiply (block [i][column], mdxMatrix [row][i]);
		if (i == 0) {
			_res = _element;
		} else {
			_res = _res ^ _element;
		}
	}

	return _res;
}


// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func initialRound (ws *Workspace) error {
	ws.currentKeyBlock = ws.cipherKeyBlock;
	roundKey (ws);
	return nil;
}

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func keySchedule (round int, keyBlock [][]byte, Rcon [][]byte) [][]byte {
	rotateUp (keyBlock);
//	sBoxSubs (keyBlock, getS_box());

	return keyBlock;
}


// ==================================================================
// rotate a column up. 
// eg: column   00				01
//				01    becomes   02
//				02				03
//				03				00
// for keySchedule this is done on column 3, the last column
// ==================================================================
func rotateUp (keyBlock [][]byte) [][]byte  {
	var _temp byte = keyBlock [0][3];
	keyBlock [0][3] = keyBlock [1][3];
	keyBlock [1][3] = keyBlock [2][3];
	keyBlock [2][3] = keyBlock [3][3];
	keyBlock [3][3] = _temp;
	return keyBlock;
}


// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func makeNewBlock (rows int, cols int) [][]byte {
	_matrix := make([][]byte, rows);
	for i := range _matrix {
	    _matrix[i] = make([]byte, cols);
	}
	return _matrix;
}

// ==================================================================
// convert the data ([]byte) into a matrix ([][]byte) 
// of MATRIX_SIZE by MATRIX_SIZE
// ==================================================================
func blockFromArray (dataPacket []byte) [][]byte {
	workingBlock := makeNewBlock (MATRIX_SIZE, MATRIX_SIZE);
	for _row := range workingBlock {
		workingBlock [_row][0] = dataPacket [_row];
		workingBlock [_row][1] = dataPacket [(_row)+MATRIX_SIZE];
		workingBlock [_row][2] = dataPacket [(_row)+MATRIX_SIZE*2];
		workingBlock [_row][3] = dataPacket [(_row)+MATRIX_SIZE*3];
	}
	return workingBlock;
}

// ==================================================================
// convert the data ([]byte) into a matrix ([][]byte) 
// of MATRIX_SIZE by MATRIX_SIZE
// ==================================================================
func arrayFromBlock (workingBlock [][]byte) []byte {
	var _packet []byte = make ([]byte, MATRIX_SIZE*MATRIX_SIZE);
	var _offset int;
	for _row := range workingBlock {
		_offset = _row * MATRIX_SIZE;
		_packet [_offset]   = workingBlock [0][_row];
		_packet [_offset+1] = workingBlock [1][_row];
		_packet [_offset+2] = workingBlock [2][_row];
		_packet [_offset+3] = workingBlock [3][_row];
	}
	return _packet;
}

// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func GF_invalidMultiply (x byte) byte {
	return 0;
}

// ==================================================================
// 
// ==================================================================
func GF_multiply1 (x byte) byte {
	return x;
}

// ==================================================================
// 
// ==================================================================
func GF_multiply2 (x byte) byte {
	var z byte;
	z = x << 1;
	if (x > 0x7f) { 
		z = z ^ byte (0x1b);
	}
	return z;
}

// ==================================================================
// 
// ==================================================================
func GF_multiply3 (x byte) byte {
	x = GF_multiply2 (x) ^ x;
	return x;
}

// ==================================================================
// this function is taken from the code:
// https://github.com/kokke/tiny-AES-c/blob/master/aes.c
// ==================================================================
func multiply (x byte, y byte) byte {
	return (((y & 1) * x) ^
	((y>>1 & 1) * GF_multiply2(x)) ^
	((y>>2 & 1) * GF_multiply2(GF_multiply2(x))) ^
	((y>>3 & 1) * GF_multiply2(GF_multiply2(GF_multiply2(x)))) ^
	((y>>4 & 1) * GF_multiply2(GF_multiply2(GF_multiply2(GF_multiply2(x)))))); /* this last call to GF_multiply2() can be omitted */

}


func blockToArray (block [][]byte) []byte {
	var _array [] byte = make ([]byte, 16);
	var _index int;

	for _col := 0; _col < MATRIX_SIZE; _col++ {
		for _row := 0; _row < MATRIX_SIZE; _row++ {
			_array [_index] = block [_col][_row];
		}
	}
	return _array;
}

// ==================================================================
// ==================================================================
// ==================================================================
// ====================== encrypt ===================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func Encrypt (ws *Workspace, plainText []byte, cipherKey []byte) []byte {
	SetCipherKey (ws, cipherKey);
	// get the first 16 bytes of the text
	// convert to matrix
	SetDataBlock (ws, plainText);
	initialRound (ws);
	encryptRounds (ws);
	// TO DO
	// repeat roundKey and rounds for the next plainText block.

	return arrayFromBlock (ws.workingBlock);
}


// ==================================================================
// ==================================================================
// ==================================================================
// ====================== decrypt ===================================
// ==================================================================
// ==================================================================
// expandkey128(key);
// 
// // the last round of encryption did NOT have the mix columns
// addroundkey(data,key,10);
// rev_shiftrows(data);
// rev_subbytes(data); 
// 
// for(int i = 9; i>= 1; i--) { 
//     addroundkey(data,key,i);
//     rev_mixColumn(data);
//     rev_shiftrows(data);
//     rev_subbytes(data); 
// }
// 
// addroundkey(data,key,0);
// ==================================================================
// ==================================================================
// 10 encryptRounds fo processing. round index 0 to 9
// ==================================================================
func encryptRounds (ws *Workspace) error {
	var _noOfRounds int = NO_OF_ROUNDS;

	for _round := 0; _round < _noOfRounds; _round++ {
		ws.currentKeyBlock = ws.keyBlockList[_round];
		ws.workingBlock, _ = substitudeBytes (ws.workingBlock, ws.sBox);
		ws.workingBlock, _ = shiftRows (ws.workingBlock);
		if (_round < NO_OF_ROUNDS-1) {
			ws.workingBlock, _ = mixColumns (ws.workingBlock, ws.mdxMatrix);
		}
		roundKey (ws);
	}
	return nil;
}


func decryptRounds (ws *Workspace) error {
	for _round := NO_OF_ROUNDS-1; _round >= 0; _round-- {
		ws.currentKeyBlock = ws.keyBlockList[_round];
		roundKey (ws);
		if (_round < NO_OF_ROUNDS-1) {
			ws.workingBlock, _ = mixColumns (ws.workingBlock, ws.inv_mdxMatrix);
		}
		inverseShiftRows (ws.workingBlock);
		reverseSubstitudeBytes (ws.workingBlock, ws.inv_sBox);
	}

	return nil;
}

// ==================================================================
// decrypt function
// ==================================================================
func Decrypt (ws *Workspace, packet []byte, key []byte) ([]byte, error) {
	decryptInit (ws, packet, key);

	decryptRounds (ws);

	ws.currentKeyBlock = ws.cipherKeyBlock;
	roundKey (ws);

	return arrayFromBlock (ws.workingBlock), nil;
}



// ==================================================================
// 
// ==================================================================
func decryptInit (ws *Workspace, packet []byte, key []byte) error {
	SetDataBlock (ws, packet);
	SetCipherKey (ws, key);
	return nil;
}

// ==================================================================
// inverse rotate. for encrypt we rotated left, 
// for decrypt we rotate right.
// ==================================================================
// given a row perform 1 circular right rotate on the bytes in the row.
// eg row 1 2 3 4 becomes 4 1 2 3
// shift rightx1 is the same as shift leftx3 since the block row is 4
// ==================================================================
func shift_r1 (row []byte) []byte {
	return shift_l3 (row);
}

// ==================================================================
// given a row perform 2 circular right rotate on the bytes in the row.
// eg row 1 2 3 4 becomes 3 4 1 2.
// rotate rightx2 is the same as rotate leftx2 because there are only
// 4 items in a row
// ==================================================================
func shift_r2 (row []byte) []byte {
	return shift_l2 (row);
}


// ==================================================================
// given a row perform 3 circular right rotate on the bytes in the row.
// this is equivalent to a single right rotate
// eg row 1 2 3 4 becomes 2 3 4 1
// ==================================================================
func shift_r3 (row []byte) []byte {
	return shift_l1 (row);
}

// ==================================================================
// shiftRows takes a full block and performs:
// single right rotate on row [1], double right rotate on row [2]
// triple right rotate on [3]. row [0] is untouched
// ==================================================================
func inverseShiftRows (wBlock [][]byte) ([][]byte,error) {
	wBlock[1] = shift_r1 (wBlock[1]);
	wBlock[2] = shift_r2 (wBlock[2]);
	wBlock[3] = shift_r3 (wBlock[3]);

	return wBlock, nil;
}


// ==================================================================
// ==================================================================
// ==================================================================
// ==================================================================
// 
// ==================================================================
func reverseSubstitudeBytes (wb [][]byte, rSBox []byte) ([][]byte,error) {
	return substitudeBytes (wb, rSBox);
}


func InverseMixColumns (ws *Workspace) ([][]byte, error) {
	return mixColumns (ws.workingBlock, ws.inv_mdxMatrix );
}