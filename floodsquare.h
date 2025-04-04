#if !defined(_FLOODSQUARE_H_INCLUDED_)
#define _FLOODSQUARE_H_INCLUDED_

#include <stack>

/*! \class   CFloodSquare
 *
 *  \brief   FloodSquare main class.
 *  \author  Benoit Bottemanne
 *  \version 0.0.1
 *  \date    2005
 *
 *  long comments
 */
class CFloodSquare
{
public:
	CFloodSquare(void) ;
	~CFloodSquare(void) ;
	
	enum ETransform { evRegular, evInvert } ;
	enum EPixel     { evBlack, evWhite, evOutOfRange } ;
	enum ESalt		{ evSaltNone = 0x0000, evSalt = 0xA53C } ;
	enum EDirection { evNorth, evSouth, evEast, evWest } ;
	
	unsigned char *Create(uint32_t ulDataSize) ;

	void CardinalTransform(int nDirection, CFloodSquare::ETransform eTransform);
	void Transform(EDirection eDirection = evNorth, ETransform eTransform = evRegular) ;
	void WritePortableBitmap(std::string sFilename) ;
	void Salt(uint8_t* pData, uint32_t uSize, ESalt eSalt = evSalt) ;

	bool Decrypt(uint8_t *pData, uint32_t uSize, std::string sKey, uint8_t **ppDecrypted, uint32_t *uDecryptedSize, ESalt eSalt = evSalt, bool bDump = false);
	bool Encrypt(uint8_t *pData, uint32_t uSize, std::string sKey, uint8_t **ppEncrypted, uint32_t *uEncryptedSize, ESalt eSalt = evSalt, bool bDump = false);

	void Allocate(uint32_t uSize);

	void Destroy(void) ;

	unsigned char *_pucData ;
	unsigned char *_pucTransform ;
	unsigned char *_pucMemory ;

	uint32_t _ulDataSize ;	  // in bytes
	uint32_t _ulSquareSize ; // in bytes

	uint32_t _ulBitCount ;	  // in bits
	uint32_t _ulSquareEdge ; // in bits

	uint8_t *_pucOrgData;
	uint32_t _ulOrgDataSize;

	int _bitmapNum;

	const std::string _sHexTable;
	
private:

    /*! \fn		   inline void ulSwap (unsigned long &a, unsigned long &b)
	 *
	 *  \brief	   inline function to Swap two unsigned long integers.
	 *  \param	   'a' value will be transfered in 'b' 
	 *  \param     'b' value will be transfered in 'a'
	 *  \exception none
	 *  \return    none
	 */
	inline void ulSwap (uint32_t &a, uint32_t &b) {
        uint32_t c = a ;
        a = b ;
        b = c ;
    } ;
	
	 /*! \fn	   inline SetBit(unsigned char *puc, int bitnum)
	 *
	 *  \brief	   inline function to set a bit in an array. By 'set' understand set 
	 *             the bit value to 1, and by 'clear' understand clear bit the value to 0.
	 *  \param	   puc - the array pointer
	 *  \param     bitnum - the bit number 
	 *  \exception none
	 *  \return    none
	 */
	inline void SetBit(unsigned char *puc, int bitnum) { 
		((puc)[(bitnum) / 8] |= (0x80 >>((bitnum) % 8))) ; 
	} ;

	/*! \fn		   inline unsigned char IsSet(unsigned char *puc, int bitnum) { 
	 *
	 *  \brief	   inline function to test a if a bit is set or clear.
	 *  \param	   puc - the array pointer
	 *  \param     bitnum - the bit number 
	 *  \exception none
	 *  \return    1 if the bit is set, 0 if the bit is clear
	 */
	inline unsigned char IsSet(unsigned char *puc, int bitnum) { 
		if((puc)[(bitnum) / 8] & (0x80>>((bitnum)% 8)))  
			return 1 ;
		else
			return 0 ; 
	} ;

	uint32_t IntegerSquareRoot(uint32_t ulValue) ;

	EPixel GetPixel(uint32_t cx, uint32_t cy, uint32_t &nTransformBitCount, 
		ETransform eTransform, EDirection eDirection) ;

	void LightPixel(uint32_t cx, uint32_t cy, EDirection eDirection) ;

	void TransposeCoordinates(uint32_t &cx, uint32_t &cy, EDirection eDirection) ;
	
	struct  SPoint {
		uint32_t x;
		uint32_t y;
	};

	std::stack < SPoint > sp ;	

	struct  SLookAround  {
		int ox ;
		int oy ;
	} ;

	static const SLookAround aLookAround[4] ;	// this static member is initialized outside this class declaration.

} ;

#endif // _FLOODSQUARE_H_INCLUDED_


