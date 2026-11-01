// Package aisanitizer detects and removes invisible Unicode watermarks,
// hidden payloads and visible LLM artifacts from text.
//
// It is a static, deterministic sanitizer: it never calls a model, never
// paraphrases and never randomizes output. It removes what is in the bytes
// (zero-width characters, bidi controls, tag characters, variation
// selectors, every Default_Ignorable_Code_Point, control characters,
// citation placeholders such as ":contentReference[oaicite:0]{index=0}",
// tracking parameters, …) while preserving legitimate uses of the same
// characters in emoji sequences and in Persian, Arabic, Indic, Mongolian,
// Korean and CJK text.
//
// Quick start:
//
//	clean, report := aisanitizer.CleanText(text)
//
// Use Defaults or Preset to obtain Options, adjust switches or individual
// rules (Options.SetRule), then call Sanitize. Detect reports what Sanitize
// would change plus detect-only findings such as decoded "ASCII smuggling"
// payloads and homoglyph words. Every rule is listed by Rules.
//
// Sanitize returns valid UTF-8, is idempotent, and returns its input without
// copying when nothing changes.
package aisanitizer
