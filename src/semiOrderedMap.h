#include <math.h>

class semiOrderedMap{
	private:
		uint64_t *indexOfBirthdayHashes;
		uint32_t *indexOfBirthdays;
		int bucketSizeExponent;
		int bucketSize;
		//int discards; //This is useful for tracking performance
	public:
		~semiOrderedMap(){
			//printf("BSE:%d Discards:%d",bucketSizeExponent,discards);
			if(indexOfBirthdayHashes)
			{
				delete [] indexOfBirthdayHashes;
			}
			if(indexOfBirthdays)
			{
				delete [] indexOfBirthdays;
			}
		}
		bool allocate(int bSE){
			try
			{
				bucketSizeExponent=bSE;
				bucketSize=powf(2,bSE);
				indexOfBirthdayHashes=new uint64_t[4194304];
				indexOfBirthdays=new uint32_t[4194304];
				return true;
			}
			catch(...)
			{
				return false;
			}
			//discards=0;
		}
		uint32_t checkAdd(uint64_t birthdayHash, uint32_t nonce){
			//birthdayHash= result_hash[x] >> (64-SEARCH_SPACE_BITS);
			uint64_t bucketStart = (birthdayHash >> (20+bucketSizeExponent))*bucketSize;
			//printf("bucketStart:%lld\n",bucketStart);
			for(int i=0;i<bucketSize;i++){
				uint64_t bucketValue=indexOfBirthdayHashes[bucketStart+i];
				if(bucketValue==birthdayHash){
					//Found matching hash, return birthday
					return indexOfBirthdays[bucketStart+i];
				}else if(bucketValue==0){
					//No match, add to index
					indexOfBirthdayHashes[bucketStart+i]=birthdayHash;
					indexOfBirthdays[bucketStart+i]=nonce;
					return 0;
				}
				//bucket contains element at this place, but not a match, increment
			}
			//bucket full
			//discards++;
			return 0;
		}
};
