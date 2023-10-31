#include <iostream>
#include <vector>
#include <cassert>

#include "DetourHooking.hpp"
using namespace DetourHooking;

#include "Common.hpp"

long MyFactorial(long a);
long MySum(long a, long b);

DetourHooking::RefCountedHook factorialHook{ factorial, MyFactorial, INSTRUCTION_LENGTH };
DetourHooking::RefCountedHook sumHook{ sum, MySum, INSTRUCTION_LENGTH };

long MyFactorial(long a)
{
	return reinterpret_cast<FactorialFunc>(factorialHook.getTrampoline())(a) + 123;
}

long MySum(long a, long b)
{
	return reinterpret_cast<SumFunc>(sumHook.getTrampoline())(a, b) + 123;
}

void printStatus(const std::string& message)
{
	std::cout << "------- "
			<< message
			  << " -------"
			  << "\nStatus:\n"
			  << "Factorial hook:\nReference counter: "
			  << factorialHook.getReferenceCounter()
			  << "\nEnabled: " << std::boolalpha << factorialHook.isEnabled() << std::noboolalpha
			  << "\nSum hook:\nReference counter: "
			  << sumHook.getReferenceCounter()
			  << "\nEnabled: " << std::boolalpha << sumHook.isEnabled() << std::noboolalpha
			  << std::endl;

	assert(factorial(5) == factorialHook.isEnabled() ? 120 + 123 : 120);
	assert(sum(2, 5) == factorialHook.isEnabled() ? 7 + 123 : 7);
}

struct Feature {
	virtual ~Feature() = default;

	virtual void enable() = 0;
	virtual void disable() = 0;
};

struct FeatureA : public Feature {
	void enable() override
	{
		factorialHook.acquire();
	}
	void disable() override
	{
		factorialHook.release();
		printStatus("FeatureA released factorialHook");
	}
};

struct FeatureB : public Feature {
	void enable() override
	{
		sumHook.acquire();
		printStatus("FeatureB acquired sumHook");
	}
	void disable() override
	{
		sumHook.release();
		printStatus("FeatureB released sumHook");
	}
};

struct FeatureC : public Feature {
	void enable() override
	{
		factorialHook.acquire();
		sumHook.acquire();
		printStatus("FeatureC acquired both hooks");
	}
	void disable() override
	{
		sumHook.release();
		factorialHook.release();
		printStatus("FeatureC released both hooks");
	}
};

int main()
{
	std::vector<std::unique_ptr<Feature>> features;
	features.emplace_back(std::move(std::make_unique<FeatureA>()));
	features.emplace_back(std::move(std::make_unique<FeatureB>()));
	features.emplace_back(std::move(std::make_unique<FeatureC>()));

	printStatus("Initial state");

	for (auto& feature : features) {
		feature->enable();
	}

	for (auto& feature : features) {
		feature->disable();
	}

	return 0;
}