
typedef struct CSTypeRef {
    void* csCppData;
    void* csCppObj;
} CSTypeRef;

#define kCSNull ((CSTypeRef) {NULL, NULL})
#define kCSNow  0x80000000u

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSymbolRef;

typedef struct CSRange {
   unsigned long long location;
   unsigned long long length;
} CSRange;

typedef void (^CSSymbolOwnerIterator)(CSSymbolOwnerRef owner);
typedef void (^CSSymbolIterator)(CSSymbolRef symbol);