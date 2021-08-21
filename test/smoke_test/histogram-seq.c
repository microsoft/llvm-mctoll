// REQUIRES: system-linux
// RUN: clang -O1 -o %t %s
// RUN: llvm-mctoll -d --include-files=/usr/include/ctype.h,/usr/include/fcntl.h,/usr/include/stddef.h,/usr/include/stdio.h,/usr/include/stdlib.h,/usr/include/string.h,/usr/include/strings.h,/usr/include/sys/mman.h,/usr/include/sys/stat.h,/usr/include/unistd.h %t
// RUN: clang -o %t1 %t-dis.ll
// RUN: %t1 2>&1 | FileCheck %s
// CHECK: No need to swap
// CHECK: This file has 192 bytes of image data, 64 pixels
// CHECK: Starting sequential histogram
// CHECK: Blue
// CHECK: ----------
// CHECK: 0 - 0
// CHECK: 1 - 0
// CHECK: 2 - 0
// CHECK: 3 - 0
// CHECK: 4 - 0
// CHECK: 5 - 0
// CHECK: 6 - 0
// CHECK: 7 - 0
// CHECK: 8 - 0
// CHECK: 9 - 0
// CHECK: 10 - 0
// CHECK: 11 - 0
// CHECK: 12 - 0
// CHECK: 13 - 0
// CHECK: 14 - 0
// CHECK: 15 - 0
// CHECK: 16 - 0
// CHECK: 17 - 0
// CHECK: 18 - 0
// CHECK: 19 - 0
// CHECK: 20 - 0
// CHECK: 21 - 0
// CHECK: 22 - 0
// CHECK: 23 - 0
// CHECK: 24 - 0
// CHECK: 25 - 0
// CHECK: 26 - 0
// CHECK: 27 - 0
// CHECK: 28 - 0
// CHECK: 29 - 0
// CHECK: 30 - 0
// CHECK: 31 - 0
// CHECK: 32 - 0
// CHECK: 33 - 0
// CHECK: 34 - 0
// CHECK: 35 - 0
// CHECK: 36 - 0
// CHECK: 37 - 0
// CHECK: 38 - 0
// CHECK: 39 - 0
// CHECK: 40 - 0
// CHECK: 41 - 0
// CHECK: 42 - 0
// CHECK: 43 - 0
// CHECK: 44 - 0
// CHECK: 45 - 0
// CHECK: 46 - 0
// CHECK: 47 - 0
// CHECK: 48 - 0
// CHECK: 49 - 0
// CHECK: 50 - 0
// CHECK: 51 - 0
// CHECK: 52 - 0
// CHECK: 53 - 0
// CHECK: 54 - 0
// CHECK: 55 - 0
// CHECK: 56 - 0
// CHECK: 57 - 0
// CHECK: 58 - 0
// CHECK: 59 - 0
// CHECK: 60 - 0
// CHECK: 61 - 0
// CHECK: 62 - 0
// CHECK: 63 - 0
// CHECK: 64 - 0
// CHECK: 65 - 0
// CHECK: 66 - 0
// CHECK: 67 - 0
// CHECK: 68 - 0
// CHECK: 69 - 1
// CHECK: 70 - 0
// CHECK: 71 - 0
// CHECK: 72 - 0
// CHECK: 73 - 0
// CHECK: 74 - 0
// CHECK: 75 - 1
// CHECK: 76 - 0
// CHECK: 77 - 0
// CHECK: 78 - 0
// CHECK: 79 - 0
// CHECK: 80 - 1
// CHECK: 81 - 3
// CHECK: 82 - 1
// CHECK: 83 - 3
// CHECK: 84 - 0
// CHECK: 85 - 1
// CHECK: 86 - 1
// CHECK: 87 - 0
// CHECK: 88 - 2
// CHECK: 89 - 0
// CHECK: 90 - 3
// CHECK: 91 - 4
// CHECK: 92 - 0
// CHECK: 93 - 1
// CHECK: 94 - 2
// CHECK: 95 - 1
// CHECK: 96 - 1
// CHECK: 97 - 1
// CHECK: 98 - 1
// CHECK: 99 - 1
// CHECK: 100 - 0
// CHECK: 101 - 2
// CHECK: 102 - 1
// CHECK: 103 - 4
// CHECK: 104 - 0
// CHECK: 105 - 0
// CHECK: 106 - 2
// CHECK: 107 - 1
// CHECK: 108 - 1
// CHECK: 109 - 3
// CHECK: 110 - 1
// CHECK: 111 - 1
// CHECK: 112 - 0
// CHECK: 113 - 2
// CHECK: 114 - 2
// CHECK: 115 - 0
// CHECK: 116 - 2
// CHECK: 117 - 0
// CHECK: 118 - 0
// CHECK: 119 - 0
// CHECK: 120 - 1
// CHECK: 121 - 1
// CHECK: 122 - 0
// CHECK: 123 - 0
// CHECK: 124 - 0
// CHECK: 125 - 0
// CHECK: 126 - 1
// CHECK: 127 - 1
// CHECK: 128 - 0
// CHECK: 129 - 0
// CHECK: 130 - 0
// CHECK: 131 - 1
// CHECK: 132 - 1
// CHECK: 133 - 0
// CHECK: 134 - 0
// CHECK: 135 - 0
// CHECK: 136 - 0
// CHECK: 137 - 0
// CHECK: 138 - 0
// CHECK: 139 - 0
// CHECK: 140 - 0
// CHECK: 141 - 0
// CHECK: 142 - 0
// CHECK: 143 - 0
// CHECK: 144 - 1
// CHECK: 145 - 1
// CHECK: 146 - 0
// CHECK: 147 - 0
// CHECK: 148 - 0
// CHECK: 149 - 0
// CHECK: 150 - 2
// CHECK: 151 - 0
// CHECK: 152 - 0
// CHECK: 153 - 0
// CHECK: 154 - 0
// CHECK: 155 - 0
// CHECK: 156 - 0
// CHECK: 157 - 1
// CHECK: 158 - 0
// CHECK: 159 - 0
// CHECK: 160 - 0
// CHECK: 161 - 0
// CHECK: 162 - 0
// CHECK: 163 - 1
// CHECK: 164 - 0
// CHECK: 165 - 0
// CHECK: 166 - 0
// CHECK: 167 - 1
// CHECK: 168 - 0
// CHECK: 169 - 0
// CHECK: 170 - 0
// CHECK: 171 - 0
// CHECK: 172 - 0
// CHECK: 173 - 0
// CHECK: 174 - 0
// CHECK: 175 - 0
// CHECK: 176 - 0
// CHECK: 177 - 0
// CHECK: 178 - 0
// CHECK: 179 - 0
// CHECK: 180 - 0
// CHECK: 181 - 0
// CHECK: 182 - 0
// CHECK: 183 - 0
// CHECK: 184 - 0
// CHECK: 185 - 0
// CHECK: 186 - 0
// CHECK: 187 - 0
// CHECK: 188 - 0
// CHECK: 189 - 0
// CHECK: 190 - 0
// CHECK: 191 - 0
// CHECK: 192 - 0
// CHECK: 193 - 0
// CHECK: 194 - 0
// CHECK: 195 - 0
// CHECK: 196 - 0
// CHECK: 197 - 0
// CHECK: 198 - 0
// CHECK: 199 - 0
// CHECK: 200 - 0
// CHECK: 201 - 0
// CHECK: 202 - 0
// CHECK: 203 - 0
// CHECK: 204 - 0
// CHECK: 205 - 0
// CHECK: 206 - 0
// CHECK: 207 - 0
// CHECK: 208 - 0
// CHECK: 209 - 0
// CHECK: 210 - 0
// CHECK: 211 - 0
// CHECK: 212 - 0
// CHECK: 213 - 0
// CHECK: 214 - 0
// CHECK: 215 - 0
// CHECK: 216 - 0
// CHECK: 217 - 0
// CHECK: 218 - 0
// CHECK: 219 - 0
// CHECK: 220 - 0
// CHECK: 221 - 0
// CHECK: 222 - 0
// CHECK: 223 - 0
// CHECK: 224 - 0
// CHECK: 225 - 0
// CHECK: 226 - 0
// CHECK: 227 - 0
// CHECK: 228 - 0
// CHECK: 229 - 0
// CHECK: 230 - 0
// CHECK: 231 - 0
// CHECK: 232 - 0
// CHECK: 233 - 0
// CHECK: 234 - 0
// CHECK: 235 - 0
// CHECK: 236 - 0
// CHECK: 237 - 0
// CHECK: 238 - 0
// CHECK: 239 - 0
// CHECK: 240 - 0
// CHECK: 241 - 0
// CHECK: 242 - 0
// CHECK: 243 - 0
// CHECK: 244 - 0
// CHECK: 245 - 0
// CHECK: 246 - 0
// CHECK: 247 - 0
// CHECK: 248 - 0
// CHECK: 249 - 0
// CHECK: 250 - 0
// CHECK: 251 - 0
// CHECK: 252 - 0
// CHECK: 253 - 0
// CHECK: 254 - 0
// CHECK: 255 - 0
// CHECK: Green
// CHECK: ----------
// CHECK: 0 - 0
// CHECK: 1 - 0
// CHECK: 2 - 0
// CHECK: 3 - 0
// CHECK: 4 - 0
// CHECK: 5 - 0
// CHECK: 6 - 0
// CHECK: 7 - 0
// CHECK: 8 - 0
// CHECK: 9 - 0
// CHECK: 10 - 0
// CHECK: 11 - 0
// CHECK: 12 - 0
// CHECK: 13 - 0
// CHECK: 14 - 0
// CHECK: 15 - 0
// CHECK: 16 - 0
// CHECK: 17 - 0
// CHECK: 18 - 0
// CHECK: 19 - 0
// CHECK: 20 - 0
// CHECK: 21 - 0
// CHECK: 22 - 0
// CHECK: 23 - 0
// CHECK: 24 - 0
// CHECK: 25 - 0
// CHECK: 26 - 0
// CHECK: 27 - 0
// CHECK: 28 - 0
// CHECK: 29 - 0
// CHECK: 30 - 0
// CHECK: 31 - 0
// CHECK: 32 - 0
// CHECK: 33 - 0
// CHECK: 34 - 0
// CHECK: 35 - 0
// CHECK: 36 - 0
// CHECK: 37 - 0
// CHECK: 38 - 0
// CHECK: 39 - 0
// CHECK: 40 - 0
// CHECK: 41 - 0
// CHECK: 42 - 0
// CHECK: 43 - 1
// CHECK: 44 - 2
// CHECK: 45 - 0
// CHECK: 46 - 0
// CHECK: 47 - 0
// CHECK: 48 - 1
// CHECK: 49 - 0
// CHECK: 50 - 0
// CHECK: 51 - 1
// CHECK: 52 - 0
// CHECK: 53 - 1
// CHECK: 54 - 0
// CHECK: 55 - 0
// CHECK: 56 - 1
// CHECK: 57 - 0
// CHECK: 58 - 1
// CHECK: 59 - 1
// CHECK: 60 - 0
// CHECK: 61 - 1
// CHECK: 62 - 1
// CHECK: 63 - 0
// CHECK: 64 - 0
// CHECK: 65 - 0
// CHECK: 66 - 1
// CHECK: 67 - 1
// CHECK: 68 - 0
// CHECK: 69 - 2
// CHECK: 70 - 0
// CHECK: 71 - 0
// CHECK: 72 - 0
// CHECK: 73 - 0
// CHECK: 74 - 1
// CHECK: 75 - 0
// CHECK: 76 - 2
// CHECK: 77 - 0
// CHECK: 78 - 1
// CHECK: 79 - 1
// CHECK: 80 - 0
// CHECK: 81 - 1
// CHECK: 82 - 1
// CHECK: 83 - 1
// CHECK: 84 - 0
// CHECK: 85 - 0
// CHECK: 86 - 1
// CHECK: 87 - 1
// CHECK: 88 - 0
// CHECK: 89 - 0
// CHECK: 90 - 1
// CHECK: 91 - 0
// CHECK: 92 - 1
// CHECK: 93 - 1
// CHECK: 94 - 3
// CHECK: 95 - 1
// CHECK: 96 - 0
// CHECK: 97 - 2
// CHECK: 98 - 1
// CHECK: 99 - 0
// CHECK: 100 - 0
// CHECK: 101 - 0
// CHECK: 102 - 2
// CHECK: 103 - 1
// CHECK: 104 - 1
// CHECK: 105 - 0
// CHECK: 106 - 1
// CHECK: 107 - 0
// CHECK: 108 - 0
// CHECK: 109 - 1
// CHECK: 110 - 1
// CHECK: 111 - 1
// CHECK: 112 - 0
// CHECK: 113 - 0
// CHECK: 114 - 2
// CHECK: 115 - 0
// CHECK: 116 - 0
// CHECK: 117 - 0
// CHECK: 118 - 3
// CHECK: 119 - 0
// CHECK: 120 - 0
// CHECK: 121 - 1
// CHECK: 122 - 0
// CHECK: 123 - 1
// CHECK: 124 - 1
// CHECK: 125 - 1
// CHECK: 126 - 0
// CHECK: 127 - 1
// CHECK: 128 - 0
// CHECK: 129 - 0
// CHECK: 130 - 1
// CHECK: 131 - 0
// CHECK: 132 - 0
// CHECK: 133 - 0
// CHECK: 134 - 0
// CHECK: 135 - 0
// CHECK: 136 - 0
// CHECK: 137 - 0
// CHECK: 138 - 0
// CHECK: 139 - 1
// CHECK: 140 - 0
// CHECK: 141 - 0
// CHECK: 142 - 0
// CHECK: 143 - 1
// CHECK: 144 - 0
// CHECK: 145 - 0
// CHECK: 146 - 1
// CHECK: 147 - 0
// CHECK: 148 - 0
// CHECK: 149 - 0
// CHECK: 150 - 0
// CHECK: 151 - 0
// CHECK: 152 - 0
// CHECK: 153 - 1
// CHECK: 154 - 0
// CHECK: 155 - 0
// CHECK: 156 - 1
// CHECK: 157 - 0
// CHECK: 158 - 1
// CHECK: 159 - 0
// CHECK: 160 - 0
// CHECK: 161 - 1
// CHECK: 162 - 0
// CHECK: 163 - 0
// CHECK: 164 - 0
// CHECK: 165 - 0
// CHECK: 166 - 0
// CHECK: 167 - 0
// CHECK: 168 - 0
// CHECK: 169 - 0
// CHECK: 170 - 0
// CHECK: 171 - 0
// CHECK: 172 - 1
// CHECK: 173 - 0
// CHECK: 174 - 0
// CHECK: 175 - 0
// CHECK: 176 - 0
// CHECK: 177 - 0
// CHECK: 178 - 0
// CHECK: 179 - 0
// CHECK: 180 - 0
// CHECK: 181 - 1
// CHECK: 182 - 0
// CHECK: 183 - 0
// CHECK: 184 - 0
// CHECK: 185 - 0
// CHECK: 186 - 0
// CHECK: 187 - 0
// CHECK: 188 - 0
// CHECK: 189 - 0
// CHECK: 190 - 1
// CHECK: 191 - 0
// CHECK: 192 - 0
// CHECK: 193 - 0
// CHECK: 194 - 0
// CHECK: 195 - 0
// CHECK: 196 - 0
// CHECK: 197 - 0
// CHECK: 198 - 0
// CHECK: 199 - 0
// CHECK: 200 - 0
// CHECK: 201 - 0
// CHECK: 202 - 0
// CHECK: 203 - 0
// CHECK: 204 - 0
// CHECK: 205 - 0
// CHECK: 206 - 0
// CHECK: 207 - 0
// CHECK: 208 - 0
// CHECK: 209 - 0
// CHECK: 210 - 0
// CHECK: 211 - 0
// CHECK: 212 - 0
// CHECK: 213 - 0
// CHECK: 214 - 0
// CHECK: 215 - 0
// CHECK: 216 - 0
// CHECK: 217 - 0
// CHECK: 218 - 0
// CHECK: 219 - 0
// CHECK: 220 - 0
// CHECK: 221 - 0
// CHECK: 222 - 0
// CHECK: 223 - 0
// CHECK: 224 - 0
// CHECK: 225 - 0
// CHECK: 226 - 0
// CHECK: 227 - 0
// CHECK: 228 - 0
// CHECK: 229 - 0
// CHECK: 230 - 0
// CHECK: 231 - 0
// CHECK: 232 - 0
// CHECK: 233 - 0
// CHECK: 234 - 0
// CHECK: 235 - 0
// CHECK: 236 - 0
// CHECK: 237 - 0
// CHECK: 238 - 0
// CHECK: 239 - 0
// CHECK: 240 - 0
// CHECK: 241 - 0
// CHECK: 242 - 0
// CHECK: 243 - 0
// CHECK: 244 - 0
// CHECK: 245 - 0
// CHECK: 246 - 0
// CHECK: 247 - 0
// CHECK: 248 - 0
// CHECK: 249 - 0
// CHECK: 250 - 0
// CHECK: 251 - 0
// CHECK: 252 - 0
// CHECK: 253 - 0
// CHECK: 254 - 0
// CHECK: 255 - 0
// CHECK: Red
// CHECK: ----------
// CHECK: 0 - 0
// CHECK: 1 - 0
// CHECK: 2 - 0
// CHECK: 3 - 0
// CHECK: 4 - 0
// CHECK: 5 - 0
// CHECK: 6 - 0
// CHECK: 7 - 0
// CHECK: 8 - 0
// CHECK: 9 - 0
// CHECK: 10 - 0
// CHECK: 11 - 0
// CHECK: 12 - 0
// CHECK: 13 - 0
// CHECK: 14 - 0
// CHECK: 15 - 0
// CHECK: 16 - 0
// CHECK: 17 - 0
// CHECK: 18 - 0
// CHECK: 19 - 0
// CHECK: 20 - 0
// CHECK: 21 - 0
// CHECK: 22 - 0
// CHECK: 23 - 0
// CHECK: 24 - 0
// CHECK: 25 - 0
// CHECK: 26 - 0
// CHECK: 27 - 0
// CHECK: 28 - 0
// CHECK: 29 - 0
// CHECK: 30 - 0
// CHECK: 31 - 0
// CHECK: 32 - 0
// CHECK: 33 - 0
// CHECK: 34 - 0
// CHECK: 35 - 0
// CHECK: 36 - 0
// CHECK: 37 - 0
// CHECK: 38 - 0
// CHECK: 39 - 0
// CHECK: 40 - 0
// CHECK: 41 - 0
// CHECK: 42 - 0
// CHECK: 43 - 0
// CHECK: 44 - 0
// CHECK: 45 - 0
// CHECK: 46 - 0
// CHECK: 47 - 0
// CHECK: 48 - 0
// CHECK: 49 - 0
// CHECK: 50 - 0
// CHECK: 51 - 0
// CHECK: 52 - 0
// CHECK: 53 - 0
// CHECK: 54 - 0
// CHECK: 55 - 0
// CHECK: 56 - 0
// CHECK: 57 - 0
// CHECK: 58 - 0
// CHECK: 59 - 0
// CHECK: 60 - 0
// CHECK: 61 - 0
// CHECK: 62 - 0
// CHECK: 63 - 0
// CHECK: 64 - 0
// CHECK: 65 - 0
// CHECK: 66 - 0
// CHECK: 67 - 0
// CHECK: 68 - 0
// CHECK: 69 - 0
// CHECK: 70 - 0
// CHECK: 71 - 0
// CHECK: 72 - 0
// CHECK: 73 - 0
// CHECK: 74 - 0
// CHECK: 75 - 0
// CHECK: 76 - 0
// CHECK: 77 - 0
// CHECK: 78 - 0
// CHECK: 79 - 0
// CHECK: 80 - 0
// CHECK: 81 - 0
// CHECK: 82 - 0
// CHECK: 83 - 0
// CHECK: 84 - 0
// CHECK: 85 - 0
// CHECK: 86 - 0
// CHECK: 87 - 0
// CHECK: 88 - 0
// CHECK: 89 - 0
// CHECK: 90 - 0
// CHECK: 91 - 0
// CHECK: 92 - 0
// CHECK: 93 - 0
// CHECK: 94 - 0
// CHECK: 95 - 0
// CHECK: 96 - 0
// CHECK: 97 - 0
// CHECK: 98 - 0
// CHECK: 99 - 0
// CHECK: 100 - 0
// CHECK: 101 - 0
// CHECK: 102 - 0
// CHECK: 103 - 1
// CHECK: 104 - 1
// CHECK: 105 - 0
// CHECK: 106 - 0
// CHECK: 107 - 0
// CHECK: 108 - 0
// CHECK: 109 - 0
// CHECK: 110 - 0
// CHECK: 111 - 0
// CHECK: 112 - 1
// CHECK: 113 - 0
// CHECK: 114 - 1
// CHECK: 115 - 0
// CHECK: 116 - 0
// CHECK: 117 - 0
// CHECK: 118 - 0
// CHECK: 119 - 1
// CHECK: 120 - 0
// CHECK: 121 - 0
// CHECK: 122 - 0
// CHECK: 123 - 1
// CHECK: 124 - 1
// CHECK: 125 - 0
// CHECK: 126 - 1
// CHECK: 127 - 0
// CHECK: 128 - 0
// CHECK: 129 - 0
// CHECK: 130 - 0
// CHECK: 131 - 0
// CHECK: 132 - 0
// CHECK: 133 - 0
// CHECK: 134 - 0
// CHECK: 135 - 1
// CHECK: 136 - 1
// CHECK: 137 - 0
// CHECK: 138 - 0
// CHECK: 139 - 0
// CHECK: 140 - 0
// CHECK: 141 - 0
// CHECK: 142 - 0
// CHECK: 143 - 0
// CHECK: 144 - 2
// CHECK: 145 - 0
// CHECK: 146 - 2
// CHECK: 147 - 0
// CHECK: 148 - 0
// CHECK: 149 - 0
// CHECK: 150 - 1
// CHECK: 151 - 0
// CHECK: 152 - 0
// CHECK: 153 - 1
// CHECK: 154 - 0
// CHECK: 155 - 0
// CHECK: 156 - 0
// CHECK: 157 - 0
// CHECK: 158 - 0
// CHECK: 159 - 1
// CHECK: 160 - 0
// CHECK: 161 - 0
// CHECK: 162 - 0
// CHECK: 163 - 0
// CHECK: 164 - 0
// CHECK: 165 - 0
// CHECK: 166 - 1
// CHECK: 167 - 2
// CHECK: 168 - 0
// CHECK: 169 - 0
// CHECK: 170 - 0
// CHECK: 171 - 0
// CHECK: 172 - 0
// CHECK: 173 - 0
// CHECK: 174 - 0
// CHECK: 175 - 0
// CHECK: 176 - 1
// CHECK: 177 - 2
// CHECK: 178 - 2
// CHECK: 179 - 0
// CHECK: 180 - 1
// CHECK: 181 - 0
// CHECK: 182 - 0
// CHECK: 183 - 3
// CHECK: 184 - 0
// CHECK: 185 - 1
// CHECK: 186 - 2
// CHECK: 187 - 0
// CHECK: 188 - 0
// CHECK: 189 - 0
// CHECK: 190 - 0
// CHECK: 191 - 0
// CHECK: 192 - 3
// CHECK: 193 - 2
// CHECK: 194 - 2
// CHECK: 195 - 1
// CHECK: 196 - 0
// CHECK: 197 - 1
// CHECK: 198 - 1
// CHECK: 199 - 2
// CHECK: 200 - 0
// CHECK: 201 - 0
// CHECK: 202 - 0
// CHECK: 203 - 1
// CHECK: 204 - 1
// CHECK: 205 - 1
// CHECK: 206 - 0
// CHECK: 207 - 2
// CHECK: 208 - 1
// CHECK: 209 - 0
// CHECK: 210 - 0
// CHECK: 211 - 0
// CHECK: 212 - 1
// CHECK: 213 - 1
// CHECK: 214 - 1
// CHECK: 215 - 0
// CHECK: 216 - 1
// CHECK: 217 - 2
// CHECK: 218 - 0
// CHECK: 219 - 1
// CHECK: 220 - 1
// CHECK: 221 - 0
// CHECK: 222 - 2
// CHECK: 223 - 0
// CHECK: 224 - 0
// CHECK: 225 - 0
// CHECK: 226 - 0
// CHECK: 227 - 1
// CHECK: 228 - 0
// CHECK: 229 - 0
// CHECK: 230 - 0
// CHECK: 231 - 2
// CHECK: 232 - 0
// CHECK: 233 - 1
// CHECK: 234 - 0
// CHECK: 235 - 0
// CHECK: 236 - 0
// CHECK: 237 - 0
// CHECK: 238 - 0
// CHECK: 239 - 0
// CHECK: 240 - 0
// CHECK: 241 - 0
// CHECK: 242 - 0
// CHECK: 243 - 0
// CHECK: 244 - 0
// CHECK: 245 - 0
// CHECK: 246 - 0
// CHECK: 247 - 0
// CHECK: 248 - 0
// CHECK: 249 - 0
// CHECK: 250 - 0
// CHECK: 251 - 0
// CHECK: 252 - 0
// CHECK: 253 - 0
// CHECK: 254 - 0
// CHECK: 255 - 0
// CHECK-EMPTY

// Adapted from phoenix-2.0 histogram-seq.c

/* Copyright (c) 2007-2009, Stanford University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Stanford University nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY STANFORD UNIVERSITY ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL STANFORD UNIVERSITY BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define IMG_DATA_OFFSET_POS 10
#define BITS_PER_PIXEL_POS 28

int swap; // to indicate if we need to swap byte order of header information

/* test_endianess
 *
 */
void test_endianess() {
  unsigned int num = 0x12345678;
  char *low = (char *)(&(num));
  if (*low == 0x78) {
    printf("No need to swap\n");
    swap = 0;
  } else if (*low == 0x12) {
    printf("Need to swap\n");
    swap = 1;
  } else {
    printf("Error: Invalid value found in memory\n");
    exit(1);
  }
}

/* swap_bytes
 *
 */
void swap_bytes(char *bytes, int num_bytes) {
  int i;
  char tmp;

  for (i = 0; i < num_bytes >> 1; i++) {
    printf("Swapping %d and %d\n", bytes[i], bytes[num_bytes - i - 1]);
    tmp = bytes[i];
    bytes[i] = bytes[num_bytes - i - 1];
    bytes[num_bytes - i - 1] = tmp;
  }
}

int main(void) {
  int i;
  struct stat finfo;
  int red[256];
  int green[256];
  int blue[256];

  // mocking file reading
  finfo.st_size = 330;
  // resized 8x8 lenna.bmp
  char fdata[330] = {
      66,   77,   74,   1,    0,    0,    0,    0,    0,   0,    -118, 0,
      0,    0,    124,  0,    0,    0,    8,    0,    0,   0,    8,    0,
      0,    0,    1,    0,    24,   0,    0,    0,    0,   0,    -64,  0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,   0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    -1,  0,    0,    -1,
      0,    0,    -1,   0,    0,    0,    0,    0,    0,   -1,   66,   71,
      82,   115,  -113, -62,  -11,  40,   81,   -72,  30,  21,   30,   -123,
      -21,  1,    51,   51,   51,   19,   102,  102,  102, 38,   102,  102,
      102,  6,    -103, -103, -103, 9,    61,   10,   -41, 3,    40,   92,
      -113, 50,   0,    0,    0,    0,    0,    0,    0,   0,    0,    0,
      0,    0,    4,    0,    0,    0,    0,    0,    0,   0,    0,    0,
      0,    0,    0,    0,    0,    0,    110,  114,  -73, 82,   48,   114,
      88,   43,   103,  80,   74,   -73,  109,  121,  -23, -106, -95,  -37,
      98,   102,  -79,  83,   69,   -103, 102,  102,  -76, 94,   59,   126,
      109,  61,   112,  69,   44,   -121, 120,  127,  -34, 121,  118,  -78,
      114,  125,  -63,  107,  118,  -64,  91,   90,   -70, 114,  76,   -110,
      103,  66,   123,  75,   58,   -97,  113,  109,  -39, 81,   56,   -120,
      116,  124,  -62,  -106, -66,  -25,  91,   94,   -62, 103,  81,   -89,
      90,   44,   104,  103,  94,   -78,  127,  -126, -25, 91,   67,   -106,
      106,  103,  -80,  -125, -100, -40,  93,   98,   -57, 86,   86,   -63,
      97,   79,   -89,  94,   51,   119,  -112, -110, -48, 111,  97,   -90,
      88,   69,   -112, -124, -113, -44,  90,   94,   -58, 85,   83,   -70,
      101,  104,  -49,  126,  114,  -64,  -99,  -98,  -53, -89,  -75,  -34,
      108,  87,   -110, 116,  118,  -61,  91,   97,   -57, 83,   76,   -73,
      90,   82,   -64,  -111, -103, -42,  -93,  -84,  -39, 106,  106,  -52,
      99,   93,   -79,  81,   53,   124,  103,  123,  -36, 83,   78,   -71,
      95,   95,   -49,  109,  111,  -51,  96,   92,   -59, 101,  110,  -43,
      113,  -117, -29,  81,   62,   -112};

  if ((fdata[0] != 'B') || (fdata[1] != 'M')) {
    printf("File is not a valid bitmap file. Exiting\n");
    exit(1);
  }

  test_endianess(); // will set the variable "swap"

  unsigned short *bitsperpixel =
      (unsigned short *)(&(fdata[BITS_PER_PIXEL_POS]));
  if (swap) {
    swap_bytes((char *)(bitsperpixel), sizeof(*bitsperpixel));
  }
  if (*bitsperpixel != 24) { // ensure its 3 bytes per pixel
    printf("Error: Invalid bitmap format - ");
    printf("This application only accepts 24-bit pictures. Exiting\n");
    exit(1);
  }

  unsigned short *data_pos = (unsigned short *)(&(fdata[IMG_DATA_OFFSET_POS]));
  if (swap) {
    swap_bytes((char *)(data_pos), sizeof(*data_pos));
  }

  int imgdata_bytes = (int)finfo.st_size - (int)(*(data_pos));
  printf("This file has %d bytes of image data, %d pixels\n", imgdata_bytes,
         imgdata_bytes / 3);

  printf("Starting sequential histogram\n");

  memset(&(red[0]), 0, sizeof(int) * 2 << 7);
  memset(&(green[0]), 0, sizeof(int) * 2 << 7);
  memset(&(blue[0]), 0, sizeof(int) * 2 << 7);

  for (i = *data_pos; i < finfo.st_size; i += 3) {
    unsigned char *val = (unsigned char *)&(fdata[i]);
    blue[*val]++;

    val = (unsigned char *)&(fdata[i + 1]);
    green[*val]++;

    val = (unsigned char *)&(fdata[i + 2]);
    red[*val]++;
  }

  printf("Blue\n");
  printf("----------\n");
  for (i = 0; i < 256; i++) {
    printf("%d - %d\n", i, blue[i]);
  }

  printf("Green\n");
  printf("----------\n");
  for (i = 0; i < 256; i++) {
    printf("%d - %d\n", i, green[i]);
  }

  printf("Red\n");
  printf("----------\n");
  for (i = 0; i < 256; i++) {
    printf("%d - %d\n", i, red[i]);
  }

  return 0;
}
