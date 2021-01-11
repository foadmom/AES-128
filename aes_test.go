package aes128

import (
	"bytes"
	"testing"
)

type data struct {
	name 		string;
	block 		[][]byte;
	key  		[]byte;
	expected	[][]byte;
}
var testData []data = []data { 
										{"sequence", 
											[][]byte { 
												{0,4,8,12},
												{1,5,9,13},
												{2,6,10,14},
												{3,7,11,15},
											}, 
											[]byte {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0},
											[][]byte { 
												{15,10,5,0},
												{10,15,0,5},
												{5,0,15,10},
												{0,5,10,15},
											}, 
										 },
									};

func compareBlocks (got [][]byte, expected [][]byte) bool {
	var _rows int = len (got);
	for i:=0; i<_rows; i++ {
		if (bytes.Compare (got [i], expected [i]) != 0) {
			return false;
		}
	}
	return true;
}

func compareBlockArray (got [][][]byte, expected [][][]byte) bool {
	var _noOfGots int = len (got);
	var _noOfExpected int = len (expected);
	if (_noOfExpected != _noOfGots) {
		return false;
	}

	for i:=0; i<_noOfGots; i++ {
		if (compareBlocks (got [i], expected [i]) == false) {
			return false;
		}
	}
	return true;
}


// ==================================================================
// ==================================================================
func Test_SetCipherKey (t *testing.T) {
	var _data []byte = []byte {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
	var _expected [][]byte = [][]byte {
		{0,1,2,3,196,22,68,69,250,199,215,214,230,54},
		{4,5,6,7,47,246,182,195,43,169,130,56,49,94},
		{8,9,10,11,126,252,136,48,132,40,99,67,38,247},
		{12,13,14,15,119,17,73,20,25,60,143,26,239,178},
	};
	
	var _ws *Workspace =  Initialise();
	SetCipherKey (_ws, _data);
	if (compareBlocks (_ws.currentKeyBlock,_expected) == false) {
		t.Errorf("expected % x but got % v\n", _expected, _ws.currentKeyBlock);
	}
}


func Test_SetCipherKey2 (t *testing.T) {
	var _data []byte = []byte {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	var _expected [][][]byte = [][][]byte {
		{
			{0xa0,0x88,0x23,0x2a},
			{0xfa,0x54,0xa3,0x6c},
			{0xfe,0x2c,0x39,0x76},
			{0x17,0xb1,0x39,0x05},
		},
		{
			{0xf2,0x7a,0x59,0x73},
			{0xc2,0x96,0x35,0x59},
			{0x95,0xb9,0x80,0xf6},
			{0xf2,0x43,0x7a,0x7f},
		},		
		{
			{0x3d,0x47,0x1e,0x6d},
			{0x80,0x16,0x23,0x7a},
			{0x47,0xfe,0x7e,0x88},
			{0x7d,0x3e,0x44,0x3b},
		},
		{
			{0xef,0xa8,0xb6,0xdb},
			{0x44,0x52,0x71,0x0b},
			{0xa5,0x5b,0x25,0xad},
			{0x41,0x7f,0x3b,0x00},
		},
		{
			{0xd4,0x7c,0xca,0x11},
			{0xd1,0x83,0xf2,0xf9},
			{0xc6,0x9d,0xb8,0x15},
			{0xf8,0x87,0xbc,0xbc},
		},
		{
			{0x6d,0x11,0xdb,0xca},
			{0x88,0x0b,0xf9,0x00},
			{0xa3,0x3e,0x86,0x93},
			{0x7a,0xfd,0x41,0xfd},
		},
		{
			{0x4e,0x5f,0x84,0x4e},
			{0x54,0x5f,0xa6,0xa6},
			{0xf7,0xc9,0x4f,0xdc},
			{0x0e,0xf3,0xb2,0x4f},
		},
		{
			{0xea,0xb5,0x31,0x7f},
			{0xd2,0x8d,0x2b,0x8d},
			{0x73,0xba,0xf5,0x29},
			{0x21,0xd2,0x60,0x2f},
		},
		{
			{0xac,0x19,0x28,0x57},
			{0x77,0xfa,0xd1,0x5c},
			{0x66,0xdc,0x29,0x00},
			{0xf3,0x21,0x41,0x6e},
		},
		{
			{0xd0,0xc9,0xe1,0xb6},
			{0x14,0xee,0x3f,0x63},
			{0xf9,0x25,0x0c,0x0c},
			{0xa8,0x89,0xc8,0xa6},
		},
};
	
	var _ws *Workspace =  Initialise();
	SetCipherKey (_ws, _data);
	// need to compare _ws.keyBlockList with the modified _expected
	if (compareBlockArray (_ws.keyBlockList,_expected) == false) {
		t.Errorf("\nexpected % x \nbut got  % x\n", _expected, _ws.keyBlockList);
	}
}


// ==================================================================
// ==================================================================
func Test_SetDataBlock (t *testing.T) {
	var _data []byte = []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	var _expected [][]byte = [][]byte {
		{0,4,8,12},
		{1,5,9,13},
		{2,6,10,14},
		{3,7,11,15},
	};

	var _ws *Workspace =  Initialise();
	SetDataBlock (_ws, _data);
	if (compareBlocks (_ws.workingBlock, _expected) == false) {
		t.Errorf("Test_SetDataBlock: expected % x but got % v\n", _expected, _ws.workingBlock);
	}
}


// ==================================================================
// ==================================================================
func Test_roundKey (t *testing.T) {
	var _data []byte = []byte {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	var _key []byte = []byte {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
	var _expected [][]byte = [][]byte {
		{0,5,10,15},
		{5,0,15,10},
		{10,15,0,5},
		{15,10,5,0},
	};

	var _ws *Workspace =  Initialise();
	SetCipherKey (_ws, _key);
	SetDataBlock (_ws, _data);
	_ws.currentKeyBlock = _ws.cipherKeyBlock;

	roundKey (_ws);
	if (compareBlocks (_ws.workingBlock, _expected) == false) {
		t.Errorf("Test_roundKey: expected % x but got % v\n", _expected, _ws.workingBlock);
	}
}

// ==================================================================
// ==================================================================
func Test_substitudeBytes (t *testing.T) {
	var _data []byte = []byte {0,0x17,0x24,0x3c,0x4e,0x55,0x69,0x7b,0x86,0x90,0xa7,0xb8,0xc4,0xdf,0xea,0xff};
	var _expected [][]byte = [][]byte {
		{0x63,0x2f,0x44,0x1c},
		{0xf0,0xfc,0x60,0x9e},
		{0x36,0xf9,0x5c,0x87},
		{0xeb,0x21,0x6c,0x16},
	}
	var _ws *Workspace =  Initialise();
	SetDataBlock (_ws, _data);
	substitudeBytes (_ws.workingBlock, _ws.sBox);
	if (compareBlocks (_ws.workingBlock, _expected) == false) {
		t.Errorf("Test_substitudeBytes: expected % x but got % v\n", _expected, _ws.workingBlock);
	}
										
	return;
}



func Test_shiftRows (t *testing.T) {
	var _data []byte = []byte {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
	var _expected [][]byte = [][]byte { 
		{0, 1,  2, 3},
		{5, 6,  7, 4},
		{10,11, 8, 9},
		{15,12,13,14},
	};

	var _ws *Workspace =  Initialise();
	SetDataBlock (_ws, _data);
	shiftRows (_ws.workingBlock);
	var _res bool = compareBlocks (_ws.workingBlock, _expected);
	if (_res == false) {
		t.Errorf ("Test_shiftRows: expected \n %v\n got \n%v", _expected, _ws.workingBlock);
	}
}


func Test_mixColumns (t *testing.T) {
	var _input [][]byte = [][]byte {
		{0x63, 0xeb, 0x9f, 0xa0},
		{0x2f, 0x93, 0x92, 0xc0},
		{0xaf, 0xc7, 0xab, 0x30},
		{0xa2, 0x20, 0xcb, 0x2b},
	};
	var _expected [][]byte = [][]byte {
		{0xba, 0x84, 0xe8, 0x1b},
		{0x75, 0xa4, 0x8d, 0x40},
		{0xf4, 0x8d, 0x06, 0x7d},
		{0x7a, 0x32, 0x0e, 0x5d},
	};
	_ws := Initialise();
	_output, _ := mixColumns (_input, _ws.mdxMatrix);
	
	var _res bool = compareBlocks (_output, _expected);
	if (_res == false) {
		t.Errorf ("Test_mixColumns: expected \n %x\n got \n%x", _expected, _output);
	}
}


func Test_InverseMixColumns (t *testing.T) {
	var _input [][]byte = [][]byte {
		{0x63, 0xeb, 0x9f, 0xa0},
		{0x2f, 0x93, 0x92, 0xc0},
		{0xaf, 0xc7, 0xab, 0x30},
		{0xa2, 0x20, 0xcb, 0x2b},
	};
	var _expected [][]byte = [][]byte {
		{0x63, 0xeb, 0x9f, 0xa0},
		{0x2f, 0x93, 0x92, 0xc0},
		{0xaf, 0xc7, 0xab, 0x30},
		{0xa2, 0x20, 0xcb, 0x2b},
	};
	_ws := Initialise();
	_output, _ := mixColumns (_input, _ws.mdxMatrix);
	_output, _  = mixColumns (_output, _ws.inv_mdxMatrix);
	
	var _res bool = compareBlocks (_output, _expected);
	if (_res == false) {
		t.Errorf ("Test_mixColumns: expected \n %x\n got \n%x", _expected, _output);
	}
}


var key1  []byte = []byte {0x54,0x68,0x61,0x74,0x73,0x20,0x6d,0x79,0x20,0x4b,0x75,0x6e,0x67,0x20,0x46,0x75};
var data1 []byte = []byte {0x54,0x77,0x6f,0x20,0x4f,0x6e,0x65,0x20,0x4e,0x69,0x6e,0x65,0x20,0x54,0x77,0x6f};
func Test_initialRound (t *testing.T) {
	var _expected [][]byte = [][]byte {
		{0x00,0x3c,0x6e,0x47},
		{0x1f,0x4e,0x22,0x74},
		{0x0e,0x08,0x1b,0x31},
		{0x54,0x59,0x0b,0x1a},
	};
	var _ws *Workspace =  Initialise();
	SetCipherKey (_ws, key1);
	SetDataBlock (_ws, data1);
	initialRound (_ws);
	var _res bool = compareBlocks (_ws.workingBlock, _expected);
	if (_res == false) {
		t.Errorf ("Test_initialRound: expected \n %x\n got \n%x", _expected, _ws.workingBlock);
	}
}

func Test_multiply (t *testing.T) {
	var _input      []byte = []byte {0xd4, 0x63, 0x2f};
	var _multiplier []byte = []byte {0x02, 0x02, 0x03}
	var _expected   []byte = []byte {0xb3, 0xc6, 0x71};
	for i := range _input {
		_got := multiply (_input[i], _multiplier[i]);
		if (_got != _expected[i]) {
			t.Errorf ("Test_multiply: expected %x got %x\n", _expected[i], _got);
		}
	}
}





func Test_GF_multiply2 (t *testing.T) {
	var _input []byte =    []byte {0xd4, 0x63};
	var _expected []byte = []byte {0xb3,0xc6};
	for i := range _input {
		_got := GF_multiply2 (_input[i]);
		if (_got != _expected[i]) {
			t.Errorf ("Test_GF_multiply2: expected %x got %x\n", _expected[i], _got);
		}
	}
}

func Test_GF_multiply3 (t *testing.T) {
	var _input []byte =    []byte {0x2f};
	var _expected []byte = []byte {0x71};
	for i := range _input {
		_got := GF_multiply3 (_input[i]);
		if (_got != _expected[i]) {
			t.Errorf ("Test_GF_multiply3: expected %x got %x\n", _expected[i], _got);
		}
	}
}

// ==================================================================
// ====================== decrypt ===================================
// ==================================================================
func Test_reverseShiftRows (t *testing.T) {
	var _packet     []byte = []byte {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
	var _expected [][]byte = [][]byte { 
		{0, 1,  2, 3},
		{7, 4,  5, 6},
		{10,11, 8, 9},
		{13,14,15,12},
	};
	var _data [][]byte = blockFromArray (_packet);
	_output, _ := inverseShiftRows (_data);
	var _res bool = compareBlocks (_output, _expected);
	if (_res == false) {
		t.Errorf ("Test_initialRound: expected \n %x\n got \n%x", _expected, _output);
	}
}


func Test_reverseSubstitudeBytes (t *testing.T) {
	var _packet []byte = []byte {0,0x17,0x24,0x3c,0x4e,0x55,0x69,0x7b,0x86,0x90,0xa7,0xb8,0xc4,0xdf,0xea,0xff};
	var _expected [][]byte = blockFromArray (_packet);
	
	_ws := Initialise ();
	_sData, _  := substitudeBytes (_expected,  _ws.inv_sBox);
	_rsData, _ := reverseSubstitudeBytes (_sData, _ws.inv_sBox);
	if (compareBlocks (_rsData, _expected) == false) {
		t.Errorf("Test_reverseSubstitudeBytes: \nexpected % x\n but got % x\n", _expected, _rsData);
	}
										
	return;
}


func Test_arrayFromBlock (t *testing.T) {
	var _packet [][]byte = [][]byte { 
		{0,  1,  2, 3},
		{4,  5,  6, 7},
		{8,  9, 10,11},
		{12,13, 14,15},
	};
	var _expected []byte = []byte {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
	var _output []byte = arrayFromBlock (_packet);

	if (bytes.Compare (_output, _expected) != 0) {
		t.Errorf("Test_arrayFromBlock: \nexpected % x\n but got % x\n", _expected, _output);
	}
	return;
}

func Test_encypt (t *testing.T) {
	var _expected []byte = []byte {0x29,0xC3,0x50,0x5F,0x57,0x14,0x20,0xF6,0x40,0x22,0x99,0xB3,0x1A,0x02,0xD7,0x3A};
	_ws := Initialise ();
	var _got []byte = Encrypt (_ws,data1, key1);
	var _res int = bytes.Compare (_got, _expected);
	if (_res != 0) {
		t.Errorf ("Test_encypt: expected \n %x\n got \n%x", _expected, _got);
	}
}

// the following data is from the site https://www.cryptool.org/en/cto/highlights/aes-step-by-step
// the site has the states for all the stages for all the rounds so it is easy to check
var Test_decrypt_key1  []byte = []byte {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
var Test_decrypt_data1 []byte = []byte {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
func Test_decrypt (t *testing.T) {
	var _expected []byte = Test_decrypt_data1;
	_ws := Initialise ();
	var _got []byte = Encrypt (_ws, Test_decrypt_data1, Test_decrypt_key1);
	_got, _ = Decrypt (_ws, _got, Test_decrypt_key1);
	var _res int = bytes.Compare (_got, _expected);
	if (_res != 0) {
		t.Errorf ("Test_decrypt: expected \n %x\n got\n %x", _expected, _got);
	}
}


