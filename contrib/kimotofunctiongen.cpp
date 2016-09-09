
#include <stdint.h>
#include <math.h>
#include <stdio.h>

using namespace std;

int main(void)
{

float FastBlocksLimit[5040];
float SlowBlocksLimit[5040];
      
        for (uint32_t i = 1; i <= 5040 ; i++)
        {
        	FastBlocksLimit[i] = 1 + (0.7084 * pow((double(i)/144), -1.228));
        	SlowBlocksLimit[i] = 1 / FastBlocksLimit[i];
        	printf ("%u: %f - %f\n", i, FastBlocksLimit[i], SlowBlocksLimit[i]); 
        }
        
        
return 0;        
}
