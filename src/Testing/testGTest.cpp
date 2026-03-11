//! Test that GTest works
#include "gtest/gtest.h"

TEST(Math, AdditionWorks)
{
    EXPECT_EQ(1 + 1, 2);
}

TEST(Math, SubtractionWorks)
{
    EXPECT_TRUE(1 - 1 == 0);
}
