################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../Accumulator.cpp \
../AccumulatorProofOfKnowledge.cpp \
../Coin.cpp \
../CoinSpend.cpp \
../Commitment.cpp \
../Params.cpp \
../SerialNumberSignatureOfKnowledge.cpp \
../SpendMetaData.cpp \
../ParamGeneration.cpp

OBJS += \
./Accumulator.o \
./AccumulatorProofOfKnowledge.o \
./Coin.o \
./CoinSpend.o \
./Commitment.o \
./Params.o \
./SerialNumberSignatureOfKnowledge.o \
./SpendMetaData.o \
./ParamGeneration.o

CPP_DEPS += \
./Accumulator.d \
./AccumulatorProofOfKnowledge.d \
./Coin.d \
./CoinSpend.d \
./Commitment.d \
./Params.d \
./SerialNumberSignatureOfKnowledge.d \
./SpendMetaData.d \
./ParamGeneration.d

# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -fopenmp -g -L/opt/local/lib -I/opt/local/include -g -Wall -fpic -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


