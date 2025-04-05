/* 

  FloodSquare Cipher - FloodSquare.cpp
  Version 0.0.1
 
  Concept, algorithm and original code created by Benoit Bottemanne.
  Copyright (c) 2005 All Rights Reserved
  harold.glitch@gmail.com
  
  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, 
  either express or implied. Please contact the author for the specific rights and limitations.
 
    Simply compile :
      cl -c -GX floodsquare.cpp 
	  g++ -c floodsquare.cpp
 
  Written for clarity & speed.
  Assumes long is 32 bit quantity.

*/

#include <stdio.h> 
#include <cstring>
#include <fstream>
#include <iostream>

using namespace std ;

// Return codes
#define RC_ERROR   1
#define RC_SUCCESS 0

#include "floodsquare.h"

// Static member arrays can be initialized in their definitions (outside the class declaration).
const CFloodSquare::SLookAround CFloodSquare::aLookAround[4] = { { -1, 0 }, { 0, -1 }, { +1, 0 }, { 0, +1 } } ;

/*! \fn		   CFloodSquare::CFloodSquare(void)
 *
 *  \brief	   Constructor, set pointers to zero.
 *
 *  \exception none
 *  \return    none
 */
CFloodSquare::CFloodSquare(void) :
	_pucData(0),
	_pucTransform(0),
	_pucMemory(0),
	_ulSquareSize(0),
	_ulDataSize(0),
	_pucOrgData(0),
	_ulBitCount(0),
	_ulOrgDataSize(0),
	_ulSquareEdge(0),
	_sHexTable("0123456789ABCDEF") // Init the hexadecimal characters table
	

{
}
		

/*! \fn        CFloodSquare::~CFloodSquare(void)
 *
 *  \brief     Destructor, delete allocated arrays of bytes
 *
 *  \exception none
 *  \return    none
 */
CFloodSquare::~CFloodSquare(void)
{
	Destroy() ;
}

void CFloodSquare::Destroy(void)
{
	if(	_pucData ) {
		memset(_pucData, 0xff, _ulSquareSize) ;
		delete _pucData ;
	}

	if(	_pucTransform ) {
		memset(_pucTransform, 0xff, _ulSquareSize) ;
		delete _pucTransform ;
	}

	if(	_pucMemory ) {
		memset(_pucMemory, 0xff, _ulSquareSize) ;
		delete _pucMemory ;
	}

	_pucData = 0 ;
	_pucTransform = 0 ;
	_pucMemory = 0 ;
	_ulSquareSize = 0 ;
	_ulDataSize = 0 ;
}

/*! \fn		   void CCipher::CardinalTransform(int nDirection, CFloodSquare::ETransform eTransform)
*
*  \brief	   Use the FloodSquare transform to Code or Decode the data. In geography, the four cardinal
*			   directions are north, east, south and west. The nDirection argument can only be 0, 1, 2 or 3
*             0 for North, 1 for West, 2 for South, 3 for East.
*
*  \param	   int nDirection - The direction of the transform
*  \param	   CFloodSquare::ETransform eTransform - Invert or Regular transform
*  \exception none
*  \return    none
*/
void CFloodSquare::CardinalTransform(int nDirection, CFloodSquare::ETransform eTransform)
{

	switch (nDirection)
	{
	case 0:
		Transform(CFloodSquare::evNorth, eTransform);
		break;
	case 1:
		Transform(CFloodSquare::evWest, eTransform);
		break;
	case 2:
		Transform(CFloodSquare::evSouth, eTransform);
		break;
	case 3:
		Transform(CFloodSquare::evEast, eTransform);
		break;
	}
}


/*! \fn		   Encrypt(uint8_t *pData, uint32_t uSize, std::string sKey, uint8_t **pEncrypted, uint32_t *uEncryptedSize, ESalt eSalt)
*
*  \brief     Encrypt the data using the key passed in argument
*
*  \param	   std::string sKey - The key
*  \exception none
*  \return    true if success or false if the key is not composed by hex characters '0123456789ABCDEF'
*/
bool CFloodSquare::Encrypt(uint8_t *pData, uint32_t uSize, std::string sKey, uint8_t **pEncrypted, uint32_t *uEncryptedSize, ESalt eSalt, bool bDump)
{
	if(evSaltNone != eSalt)
		Salt(pData, uSize, eSalt);

	_ulOrgDataSize = uSize;
	// Allocate the data space composed by an unsigned long (to store the file size) followed by the file data
	_pucOrgData = Create(_ulOrgDataSize + sizeof(uint32_t));

	// Copy the size of the file in the data storage at offset 0
	(*(uint32_t*)_pucData) = _ulOrgDataSize;

	memcpy(_pucOrgData + sizeof(uint32_t), pData, _ulOrgDataSize);

	int nA, nB;

	for (int n = 0; n < sKey.length(); n++) {

		string::size_type pos = _sHexTable.find(toupper(sKey[n]));

		if (pos == string::npos)
			throw exception("Key is not composed by hex characters '0123456789ABCDEF'");

		// Each hex digit contain 4 bits and is sliced into 2 values of 2 bits.
		nA = (pos & 0x03);
		nB = (pos & 0x0C) >> 2;

		// Each 2 bits values (0, 1, 2, 3) code the direction of the transform (0:North - 1:West - 2:South - 3:East)
		CardinalTransform(nA, CFloodSquare::evRegular);
		CardinalTransform(nB, CFloodSquare::evRegular);

		if (bDump) {
			char numstr[32]; // enough to hold
			sprintf_s(numstr, "encrypt_%04d.pbm", _bitmapNum++);
			WritePortableBitmap(numstr);
		}		
	}

	*pEncrypted = _pucOrgData;
	*uEncryptedSize = _ulSquareSize ;

	return true;
}


/*! \fn		   Decrypt(uint8_t* pData, uint32_t uSize, std::string sKey, uint8_t** pDecrypted, uint32_t* uDecryptedSize, ESalt eSalt)
*
*  \brief     Decrypt the data using the key passed in argument
*
*  \param	   std::string sKey - The key
*  \exception none
*  \return    true if success or false if the key is not composed by hexa characters '0123456789ABCDEF'
*/
bool CFloodSquare::Decrypt(uint8_t* pData, uint32_t uSize, std::string sKey, uint8_t** pDecrypted, uint32_t* uDecryptedSize, ESalt eSalt, bool bDump)
{
	// Get input file size
	_ulOrgDataSize = uSize;
	// Allocate the data space
	_pucOrgData = Create(_ulOrgDataSize);

	memcpy(_pucTransform, pData, _ulSquareSize);

	int nA, nB;

	// For decryption, we read the key string in reverse order
	for (int n = (int)sKey.length() - 1; n >= 0; n--) {

		string::size_type pos = _sHexTable.find(toupper(sKey[n]));

		if (pos == string::npos)
			throw exception("Key is not composed by hex characters '0123456789ABCDEF'");

		// Each hex digit contain 4 bits and is sliced into 2 values of 2 bits.
		nA = (pos & 0x03);
		nB = (pos & 0x0C) >> 2;

		// Each 2 bits values (0, 1, 2, 3) code the direction of the transform (0:North - 1:West - 2:South - 3:East)
		CardinalTransform(nB, CFloodSquare::evInvert);
		CardinalTransform(nA, CFloodSquare::evInvert);

		if (bDump) {
			char numstr[32]; // enough to hold
			sprintf_s(numstr, "decrypt_%04d.pbm", _bitmapNum++);
			WritePortableBitmap(numstr);
		}
	}

	uint32_t ulSize = (*(uint32_t*)_pucOrgData);
	*uDecryptedSize = ulSize;
	*pDecrypted = _pucOrgData + sizeof(uint32_t);

	if (evSaltNone != eSalt)
		Salt(*pDecrypted, ulSize, eSalt);

	return true;
}

void CFloodSquare::Allocate(uint32_t uSize)
{
	_ulOrgDataSize = uSize;
	_pucOrgData = Create(_ulOrgDataSize + sizeof(uint32_t));
}

/*! \fn		   uint32_t CFloodSquare::IntegerSquareRoot(uint32_t ulValue) 
 *
 *  \brief     Remarkably fast integer implementation of square roots calculation.
 *
 *  \param	   ulValue - The entry value.
 *  \exception none
 *  \return    The integer square root of the entry value.
 */
uint32_t CFloodSquare::IntegerSquareRoot(uint32_t ulValue)
{
  uint32_t temp, g=0, b = 0x8000, bshft = 15 ;

  do {
    if (ulValue >= (temp = (((g<<1)+b)<<bshft--))) {
      g += b ;
      ulValue -= temp ;
    }
  } while (b >>= 1) ;

  return g ;
}

/*! \fn		   void CFloodSquare::Salt(uint8_t* pData, uint32_t uSize, ESalt eSalt)
 *
 *  \brief     Binary XOR (exclusive OR) operation on the data.  
 *             This is used to separate large bit blocks of same value. This is not an encryption method, 
 *             it is only used to increase the variability of the text data. If you use compressed data
 *             this operation is not needed because the variability of compressed data is very good (flat spectrum).
 *
 *  \param	   usValue - 16bit value.
 *  \exception none
 *  \return    none
 */
void CFloodSquare::Salt(uint8_t* pData, uint32_t uSize, ESalt eSalt)
{
	uint32_t n ;

	for(n = 0 ; n < uSize; n++) {
		if(n%2 == 0)
			pData[n] ^= (eSalt & 0x00ff) ;   // xor with LSB
		else
			pData[n] ^= (eSalt >> 8) ;		// xor with MSB
	}
}

/*! \fn		   void CFloodSquare::TransposeCoordinates(uint32_t &cx, uint32_t &cy, EDirection eDirection)
 *
 *  \brief     Modify the coordinates cx and cy passed in reference according to the cardinal direction.
 *             
 *  \param	   cx - X coordinate
 *  \param	   cy - Y coordinate
 *  \param	   eDirection - Cardinal Direction on where to turn coordinates.
 *  \exception none 
 *  \return    none
 */
void CFloodSquare::TransposeCoordinates(uint32_t &cx, uint32_t &cy, EDirection eDirection)
{
	switch(eDirection) 
	{
	case evNorth:
		// Nothing to do : coordinates stays unchanged
		break ;

	case evEast:
		ulSwap(cx, cy) ;
		cx = (_ulSquareEdge-1) - cx ;
		break ;

	case evWest:
		ulSwap(cx, cy) ;
		cy = (_ulSquareEdge-1) - cy ;
		break ;

	case evSouth:
		cy = (_ulSquareEdge-1) - cy ;
		cx = (_ulSquareEdge-1) - cx ;
		break ;
	}

}

/*! \fn		   unsigned char *CFloodSquare::Create(uint32_t ulDataSize)
 *
 *  \brief     Create the DataSquare, compute sizes and allocate areas.
 *
 *  \param	   ulDataSize - The size of the data block to load into the DataSquare.
 *  \exception std::bad_alloc() - if memory allocation fails. 
 *  \return    The pointer to the allocated data structure
 */
unsigned char *CFloodSquare::Create(uint32_t ulDataSize) 
{
	_bitmapNum = 0;
	_ulDataSize = ulDataSize ;

	// Get the size in bits (pixels)
	_ulBitCount = _ulDataSize << 3 ;		// mul 8 

	// Compute the square edge length
	_ulSquareEdge = IntegerSquareRoot (_ulBitCount) ;

	// Align the edge to the next multiple of 4
	if(_ulSquareEdge * _ulSquareEdge != _ulBitCount) {
		_ulSquareEdge += 4 ;  // add 4
		_ulSquareEdge >>= 2 ; // div 4
		_ulSquareEdge <<= 2 ; // mul 4
	}

	// Get the size in bytes 
	_ulSquareSize = (_ulSquareEdge * _ulSquareEdge) >> 3 ;	// div 8 

	// Allocate source array
	_pucData = new unsigned char [_ulSquareSize] ;

	if(0 == _pucData)
		throw std::bad_alloc() ;
	
	memset(_pucData, 0xff, _ulSquareSize) ;

	// Allocate transform array
	_pucTransform = new unsigned char [_ulSquareSize] ;	

	if(0 == _pucTransform)
		throw std::bad_alloc() ;

	memset(_pucTransform, 0x00, _ulSquareSize) ;

	// Allocate pixel memory array (already known pixel)
	_pucMemory = new unsigned char [_ulSquareSize] ;
	
	if(0 == _pucMemory)
		throw std::bad_alloc() ;

	memset(_pucMemory, 0x00, _ulSquareSize) ;
		
	return _pucData ;
}


/*! \fn		   void CFloodSquare::Transform(EDirection eDirection, ETransform eTransform)
 *
 *  \brief     The Algorithm's Heart :the FloodSquare block transform function itself. 
 * 			   After transformation, the data pointed by "_pucData" is modified.
 *
 *  \param	   eDirection - Direction on where to turn coordinates.
 *  \param	   eTransform - Type of transform, regular or invert transform.
 *  \exception none 
 *  \return    none
 */
void CFloodSquare::Transform(EDirection eDirection, ETransform eTransform)
{
	uint32_t cx ;
	uint32_t cy ;
	uint32_t nTransformBitCount = 0 ;

	if(evRegular == eTransform) {
		memset(_pucTransform, 0x00, _ulSquareSize) ;
		memset(_pucMemory, 0x00, _ulSquareSize) ;
	}
	else {
		memset(_pucData, 0x00, _ulSquareSize) ;
		memset(_pucMemory, 0x00, _ulSquareSize) ;
	}

	// For each point in the square
	for(cx = 0 ; cx < _ulSquareEdge ; cx++) {
		
		for(cy = 0 ; cy < _ulSquareEdge ; cy++) {
						
			// Found a black pixel : push coordinates on stack for later use
			if( evBlack == GetPixel(cx, cy, nTransformBitCount, eTransform, eDirection) ) {
				sp.push({ cx,cy });
			}
			
			// While the coordinates stack is not empty
			while( !sp.empty() ) {
				
				// Pop coordinates
				SPoint p = sp.top();
				sp.pop();

				// Change pixel color to white
				LightPixel(p.x, p.y, eDirection) ;
				
				// Explore around the pixel and push black pixels coordinates on stack
				for(int i = 0 ; i < sizeof(aLookAround) / sizeof(SLookAround) ; i++) {
					
					if( evBlack == GetPixel(p.x + aLookAround[i].ox, p.y + aLookAround[i].oy, nTransformBitCount, eTransform, eDirection) ) {
						sp.push({ p.x + aLookAround[i].ox, p.y + aLookAround[i].oy });
					}
				}
			}
		}
	}

	if(evRegular == eTransform)
		memcpy(_pucData, _pucTransform, _ulSquareSize) ;
	else
		memcpy(_pucTransform, _pucData, _ulSquareSize) ;
}



/*! \fn		   unsigned char CFloodSquare::GetPixel(uint32_t cx, uint32_t cy, uint32_t &nTransformBitCount, ETransform eTransform, EDirection eDirection)
 *
 *  \brief     Return the pixel value or an error code if coordinates are out of range.
 *			   This method not only get a pixel value, we also fill the transform array 
 *			   of bits (_pucTranform) in regular mode or we query this array en inverse mode.
 *			   We don't query more than one time each pixel, this is the reason why we store 
 *			   in the memory area (_pucMemory) if the pixel was requested before (already known).
 *             
 *  \param	   cx - X coordinate
 *  \param	   cy - Y coordinate
 *  \param	   eDirection - Direction on where to turn coordinates.
 *  \exception none 
 *  \return    returns evWhite or evBlack or evOutOfRange if The coordinates are out of square range.
 */
CFloodSquare::EPixel CFloodSquare::GetPixel(uint32_t cx, uint32_t cy, uint32_t &nTransformBitCount, ETransform eTransform, EDirection eDirection)
{
	TransposeCoordinates(cx, cy, eDirection) ;

	// If outside the square return "evOutOfRange"
	if( cy >= _ulSquareEdge || cx >= _ulSquareEdge) {
		return evOutOfRange ;
	} 

	// Bit already known ?
	if( IsSet(_pucMemory, cx + (_ulSquareEdge * cy) ) )
		return evWhite ;

	// Mark the bit as known !
	SetBit(_pucMemory, cx + (_ulSquareEdge * cy)) ;
	
	if(evRegular == eTransform) {

		if( IsSet(_pucData, cx + (_ulSquareEdge * cy) ) ) {
			SetBit(_pucTransform, nTransformBitCount) ;
			nTransformBitCount++ ;
			return evBlack ;
		}
	}
	else {

		if( IsSet(_pucTransform, nTransformBitCount) ) {
			nTransformBitCount++ ;
			return evBlack ;
		}
	}
	
	nTransformBitCount++ ;
	
	return evWhite ;
}

/*! \fn		   void CFloodSquare::LightPixel(uint32_t cx, uint32_t cy, EDirection eDirection)
 *
 *  \brief     Set the pixel (after having transposed the coordinates) to 'evWhite'
 *             
 *  \param	   cx - X coordinate
 *  \param	   cy - Y coordinate
 *  \param	   eDirection - Direction on where to turn coordinates.
 *  \exception none 
 *  \return    none
 */
void CFloodSquare::LightPixel(uint32_t cx, uint32_t cy, EDirection eDirection)
{
	TransposeCoordinates(cx, cy, eDirection) ;

	SetBit(_pucData, cx + (_ulSquareEdge * cy) ) ;
}

/*! \fn		   int CFloodSquare::WritePortableBitmap(char *pszFilename)
 *
 *  \brief     Write the Data into a portable bitmap file 
 *             
 *  \param	   pszFilename - The filename 
 *  \exception none 
 *  \return    none
 */
void CFloodSquare::WritePortableBitmap(std::string sFilename)
{
	uint32_t ulcx ;
	uint32_t ulcy ;
	int nchar = 0 ;
	
	std::ofstream pbmFile(sFilename.c_str(), ios::out | ios::trunc) ;

	// Write the PBM format header
	pbmFile << "P1\n# SquareData\n" << _ulSquareEdge << " " << _ulSquareEdge << "\n" ;

	// Write the bitmap bits
	for(ulcy = 0 ; ulcy < _ulSquareEdge ; ulcy++) {

		for(ulcx = 0 ; ulcx < _ulSquareEdge ; ulcx++) {

			// The character 1 appear black, 0 appear white
			IsSet(_pucData, ulcx + (_ulSquareEdge * ulcy) ) ? pbmFile << "1" : pbmFile << "0" ;

			// No line should be longer than 70 characters
			if( nchar++ == 35 ) {
				pbmFile << "\n" ;
				nchar = 0 ;
			}
			else {
				pbmFile << " " ;
			}
		}
	}

	pbmFile.close() ;
}


