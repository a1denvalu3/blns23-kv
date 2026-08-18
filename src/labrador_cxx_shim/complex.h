#pragma once
// Empty shim shadowing the system <complex.h> for the single translation
// unit src/nizk_labrador.cpp (added to its include path privately; see
// CMakeLists.txt). Background: poly.h in third_party/labrador is C99 and
// declares prototypes taking `double complex`, which is not valid C++.
// nizk_labrador.cpp defines `complex` away as a macro, but libstdc++'s
// <complex.h> re-#undefs that macro on every inclusion (the #undef sits
// outside the include guard), and poly.h includes <complex.h> itself --
// so the only robust way to keep the macro alive while poly.h is
// preprocessed is to make that inclusion resolve to this empty file.
// Nothing in that translation unit uses C complex arithmetic.
