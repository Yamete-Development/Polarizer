//! Configuration-time parsing, classification, and validation for content policies.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use uuid::Uuid;

use super::model::{
    Authority, ContentPolicy, PolicyAction, PolicyActionType, PolicyLimits, PolicyRule,
    RulePattern, WildcardPatternType,
};
use super::normalization::normalize_pattern;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPattern {
    pub normalized: String,
    pub pattern_type: WildcardPatternType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PatternErrorCode {
    Empty,
    MalformedQuotes,
    UnquotedWhitespace,
    InternalWildcard,
    UnsupportedSyntax,
    PhraseMustContainMultipleWords,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    pub code: PatternErrorCode,
    pub pattern: String,
}

impl PatternError {
    fn message(&self) -> &'static str {
        match self.code {
            PatternErrorCode::Empty => "pattern must not be empty",
            PatternErrorCode::MalformedQuotes => "pattern has malformed quotes",
            PatternErrorCode::UnquotedWhitespace => {
                "multi-word patterns must be enclosed in double quotes"
            }
            PatternErrorCode::InternalWildcard => {
                "wildcards are only permitted at the beginning and/or end"
            }
            PatternErrorCode::UnsupportedSyntax => "pattern contains unsupported syntax",
            PatternErrorCode::PhraseMustContainMultipleWords => {
                "quoted phrases must contain at least two words"
            }
        }
    }
}

impl fmt::Display for PatternError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for PatternError {}

pub fn parse_pattern(pattern: &str) -> Result<ParsedPattern, PatternError> {
    let input = pattern.trim();
    if input.is_empty() {
        return Err(pattern_error(PatternErrorCode::Empty, pattern));
    }

    let quote_count = input.chars().filter(|character| *character == '"').count();
    if quote_count > 0 {
        if quote_count != 2 || !input.starts_with('"') || !input.ends_with('"') {
            return Err(pattern_error(PatternErrorCode::MalformedQuotes, pattern));
        }
        let phrase = &input[1..input.len() - 1];
        if phrase.contains('"') {
            return Err(pattern_error(PatternErrorCode::MalformedQuotes, pattern));
        }
        let normalized_phrase = normalize_pattern(phrase);
        if normalized_phrase.is_empty() {
            return Err(pattern_error(PatternErrorCode::Empty, pattern));
        }
        if normalized_phrase.split(' ').count() < 2 {
            return Err(pattern_error(
                PatternErrorCode::PhraseMustContainMultipleWords,
                pattern,
            ));
        }
        if normalized_phrase.contains('*') || contains_unsupported_syntax(&normalized_phrase) {
            return Err(pattern_error(PatternErrorCode::UnsupportedSyntax, pattern));
        }
        return Ok(ParsedPattern {
            normalized: normalized_phrase,
            pattern_type: WildcardPatternType::Phrase,
        });
    }

    if input.chars().any(char::is_whitespace) {
        return Err(pattern_error(PatternErrorCode::UnquotedWhitespace, pattern));
    }
    if contains_unsupported_syntax(input) {
        return Err(pattern_error(PatternErrorCode::UnsupportedSyntax, pattern));
    }

    let leading_wildcard = input.starts_with('*');
    let trailing_wildcard = input.ends_with('*');
    let word_start = usize::from(leading_wildcard);
    let word_end = input.len() - usize::from(trailing_wildcard);
    let word = &input[word_start..word_end];
    if word.is_empty() {
        return Err(pattern_error(PatternErrorCode::Empty, pattern));
    }
    if word.contains('*') || input.matches('*').count() > 2 {
        return Err(pattern_error(PatternErrorCode::InternalWildcard, pattern));
    }
    let pattern_type = match (leading_wildcard, trailing_wildcard) {
        (false, false) => WildcardPatternType::ExactWord,
        (false, true) => WildcardPatternType::Prefix,
        (true, false) => WildcardPatternType::Suffix,
        (true, true) => WildcardPatternType::Contains,
    };
    let normalized = normalize_pattern(word);
    if normalized.is_empty() {
        return Err(pattern_error(PatternErrorCode::Empty, pattern));
    }
    Ok(ParsedPattern {
        normalized,
        pattern_type,
    })
}

pub fn classify_pattern(pattern: &str) -> Result<WildcardPatternType, PatternError> {
    parse_pattern(pattern).map(|parsed| parsed.pattern_type)
}

pub fn validate_policy(
    policy: &ContentPolicy,
    limits: PolicyLimits,
) -> Result<(), PolicyValidationErrors> {
    collect_validation(policy, limits, true).finish()
}

pub fn validate_and_classify_policy(
    policy: &mut ContentPolicy,
    limits: PolicyLimits,
) -> Result<(), PolicyValidationErrors> {
    let outcome = collect_validation(policy, limits, false);
    if !outcome.errors.is_empty() {
        return Err(PolicyValidationErrors::new(outcome.errors));
    }
    for rule in &mut policy.rules {
        for pattern in &mut rule.patterns {
            pattern.pattern_type = parse_pattern(&pattern.pattern)
                .expect("pattern was validated before classification")
                .pattern_type;
        }
    }
    Ok(())
}

pub fn classify_policy_patterns(policy: &mut ContentPolicy) -> Result<(), PolicyValidationErrors> {
    let mut errors = Vec::new();
    let mut classifications = BTreeMap::new();
    for rule in &policy.rules {
        for pattern in &rule.patterns {
            match parse_pattern(&pattern.pattern) {
                Ok(parsed) => {
                    classifications.insert(pattern.id, parsed.pattern_type);
                }
                Err(error) => errors.push(pattern_error_to_validation(rule, pattern, error)),
            }
        }
    }
    if !errors.is_empty() {
        return Err(PolicyValidationErrors::new(errors));
    }
    for rule in &mut policy.rules {
        for pattern in &mut rule.patterns {
            pattern.pattern_type = classifications[&pattern.id];
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationErrorCode {
    InvalidScope,
    MissingPatterns,
    MissingSurfaces,
    MissingActions,
    EmptyRuleName,
    DuplicateRuleId,
    DuplicateRuleName,
    TooManyPatterns,
    TextTooLong,
    Pattern,
    PatternClassificationMismatch,
    DuplicatePattern,
    DuplicatePatternId,
    DuplicateActionId,
    DuplicateActionType,
    IllegalAction,
    MissingDuration,
    UnexpectedDuration,
    DurationOutOfRange,
    InvalidReplacement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValidationError {
    pub code: ValidationErrorCode,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValidationErrors {
    pub errors: Vec<PolicyValidationError>,
}

impl PolicyValidationErrors {
    fn new(mut errors: Vec<PolicyValidationError>) -> Self {
        errors.sort_by(compare_validation_errors);
        errors.dedup();
        Self { errors }
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }
}

impl fmt::Display for PolicyValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.errors.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{}: {}", error.path, error.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyValidationErrors {}

impl std::ops::Deref for PolicyValidationErrors {
    type Target = [PolicyValidationError];

    fn deref(&self) -> &Self::Target {
        &self.errors
    }
}

struct ValidationOutcome {
    errors: Vec<PolicyValidationError>,
}

impl ValidationOutcome {
    fn finish(self) -> Result<(), PolicyValidationErrors> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(PolicyValidationErrors::new(self.errors))
        }
    }
}

fn collect_validation(
    policy: &ContentPolicy,
    limits: PolicyLimits,
    check_classification: bool,
) -> ValidationOutcome {
    let mut errors = Vec::new();
    if let Err(message) = policy.scope.validate() {
        errors.push(error(ValidationErrorCode::InvalidScope, "scope", message));
    }

    let pattern_count: usize = policy.rules.iter().map(|rule| rule.patterns.len()).sum();
    let pattern_limit = limits.maximum_patterns(policy.scope.authority);
    if pattern_count > pattern_limit {
        errors.push(error(
            ValidationErrorCode::TooManyPatterns,
            "patterns",
            format!(
                "{} patterns exceed the {} pattern limit for {:?}",
                pattern_count, pattern_limit, policy.scope.authority
            ),
        ));
    }

    let mut rule_ids = BTreeMap::<Uuid, Vec<&PolicyRule>>::new();
    let mut rule_names = BTreeMap::<String, Vec<&PolicyRule>>::new();
    let mut duplicate_patterns =
        BTreeMap::<(WildcardPatternType, String), Vec<(&PolicyRule, &RulePattern)>>::new();
    let mut pattern_ids = BTreeMap::<Uuid, Vec<(&PolicyRule, &RulePattern)>>::new();
    let mut action_ids = BTreeMap::<Uuid, Vec<(&PolicyRule, &PolicyAction)>>::new();

    for rule in &policy.rules {
        rule_ids.entry(rule.id).or_default().push(rule);
        rule_names
            .entry(rule.name.trim().to_lowercase())
            .or_default()
            .push(rule);
        validate_rule(
            rule,
            policy.scope.authority,
            limits,
            check_classification,
            &mut errors,
        );
        for pattern in &rule.patterns {
            pattern_ids
                .entry(pattern.id)
                .or_default()
                .push((rule, pattern));
            if let Ok(parsed) = parse_pattern(&pattern.pattern) {
                duplicate_patterns
                    .entry((parsed.pattern_type, parsed.normalized))
                    .or_default()
                    .push((rule, pattern));
            }
        }
        for action in &rule.actions {
            action_ids
                .entry(action.id)
                .or_default()
                .push((rule, action));
        }
    }

    for (id, mut rules) in rule_ids {
        if rules.len() > 1 {
            rules.sort_by_key(|rule| (rule.name.trim().to_lowercase(), rule.description.clone()));
            for rule in rules.into_iter().skip(1) {
                errors.push(error(
                    ValidationErrorCode::DuplicateRuleId,
                    rule_path(rule),
                    format!("rule id {id} is not unique"),
                ));
            }
        }
    }
    for (name, mut rules) in rule_names {
        if !name.is_empty() && rules.len() > 1 {
            rules.sort_by_key(|rule| (rule.id, rule.description.clone()));
            for rule in rules.into_iter().skip(1) {
                errors.push(error(
                    ValidationErrorCode::DuplicateRuleName,
                    rule_path(rule),
                    format!("rule name {} is not unique", rule.name),
                ));
            }
        }
    }
    for ((pattern_type, normalized), mut occurrences) in duplicate_patterns {
        if occurrences.len() > 1 {
            occurrences.sort_by_key(|(rule, pattern)| (pattern.id, rule.id));
            for (rule, pattern) in occurrences.into_iter().skip(1) {
                errors.push(error(
                    ValidationErrorCode::DuplicatePattern,
                    pattern_path(rule, pattern),
                    format!("{pattern_type:?} pattern {normalized} is duplicated"),
                ));
            }
        }
    }
    for (id, mut occurrences) in pattern_ids {
        if occurrences.len() > 1 {
            occurrences.sort_by_key(|(rule, pattern)| (rule.id, pattern.pattern.clone()));
            for (rule, pattern) in occurrences.into_iter().skip(1) {
                errors.push(error(
                    ValidationErrorCode::DuplicatePatternId,
                    pattern_path(rule, pattern),
                    format!("pattern id {id} is not unique"),
                ));
            }
        }
    }
    for (id, mut occurrences) in action_ids {
        if occurrences.len() > 1 {
            occurrences.sort_by_key(|(rule, action)| (rule.id, action.action_type));
            for (rule, action) in occurrences.into_iter().skip(1) {
                errors.push(error(
                    ValidationErrorCode::DuplicateActionId,
                    format!("{}.actions[id={}]", rule_path(rule), action.id),
                    format!("action id {id} is not unique"),
                ));
            }
        }
    }
    ValidationOutcome { errors }
}

fn validate_rule(
    rule: &PolicyRule,
    authority: Authority,
    limits: PolicyLimits,
    check_classification: bool,
    errors: &mut Vec<PolicyValidationError>,
) {
    let path = rule_path(rule);
    if rule.name.trim().is_empty() {
        errors.push(error(
            ValidationErrorCode::EmptyRuleName,
            format!("{path}.name"),
            "rule name must not be empty",
        ));
    }
    check_limit(
        errors,
        format!("{path}.name"),
        "rule name",
        &rule.name,
        limits.rule_name_characters,
    );
    check_limit(
        errors,
        format!("{path}.description"),
        "rule description",
        &rule.description,
        limits.rule_description_characters,
    );
    if let Some(reason) = &rule.custom_reason {
        check_limit(
            errors,
            format!("{path}.custom_reason"),
            "custom reason",
            reason,
            limits.custom_reason_characters,
        );
    }

    if rule.patterns.is_empty() {
        errors.push(error(
            ValidationErrorCode::MissingPatterns,
            format!("{path}.patterns"),
            "rule must contain at least one pattern",
        ));
    }
    if rule.surfaces.is_empty() {
        errors.push(error(
            ValidationErrorCode::MissingSurfaces,
            format!("{path}.surfaces"),
            "rule must contain at least one surface",
        ));
    }
    if rule.actions.is_empty() {
        errors.push(error(
            ValidationErrorCode::MissingActions,
            format!("{path}.actions"),
            "rule must contain at least one action",
        ));
    }

    for pattern in &rule.patterns {
        match parse_pattern(&pattern.pattern) {
            Ok(parsed) => {
                if check_classification && parsed.pattern_type != pattern.pattern_type {
                    errors.push(error(
                        ValidationErrorCode::PatternClassificationMismatch,
                        pattern_path(rule, pattern),
                        format!(
                            "stored pattern type {:?} does not match {:?}",
                            pattern.pattern_type, parsed.pattern_type
                        ),
                    ));
                }
                check_limit(
                    errors,
                    pattern_path(rule, pattern),
                    "pattern",
                    &pattern.pattern,
                    limits.pattern_characters,
                );
            }
            Err(parse_error) => {
                errors.push(pattern_error_to_validation(rule, pattern, parse_error));
            }
        }
    }
    for action in &rule.actions {
        validate_action(action, authority, limits, rule, errors);
    }
    let mut action_types = BTreeSet::new();
    for action in &rule.actions {
        if !action_types.insert(action.action_type) {
            errors.push(error(
                ValidationErrorCode::DuplicateActionType,
                format!("{path}.actions[id={}]", action.id),
                format!("action {:?} appears more than once", action.action_type),
            ));
        }
    }
}

fn validate_action(
    action: &PolicyAction,
    authority: Authority,
    limits: PolicyLimits,
    rule: &PolicyRule,
    errors: &mut Vec<PolicyValidationError>,
) {
    let path = format!("{}.actions[id={}]", rule_path(rule), action.id);
    let legal = match authority {
        Authority::Global => {
            action.action_type.is_delivery()
                || matches!(
                    action.action_type,
                    PolicyActionType::LobbyWarn
                        | PolicyActionType::LobbyBan
                        | PolicyActionType::Blacklist
                )
        }
        Authority::Hub => {
            action.action_type.is_delivery()
                || matches!(
                    action.action_type,
                    PolicyActionType::Log
                        | PolicyActionType::HubWarn
                        | PolicyActionType::HubMute
                        | PolicyActionType::HubBan
                )
        }
        Authority::Server => action.action_type.is_delivery(),
    };
    if !legal {
        errors.push(error(
            ValidationErrorCode::IllegalAction,
            path.clone(),
            format!(
                "action {:?} is not legal at {:?} authority",
                action.action_type, authority
            ),
        ));
    }

    if action.action_type.needs_duration() && action.duration_seconds.is_none() {
        errors.push(error(
            ValidationErrorCode::MissingDuration,
            path.clone(),
            format!("action {:?} requires a duration", action.action_type),
        ));
    }
    if !action.action_type.allows_duration() && action.duration_seconds.is_some() {
        errors.push(error(
            ValidationErrorCode::UnexpectedDuration,
            path.clone(),
            format!("action {:?} does not accept a duration", action.action_type),
        ));
    }
    if let Some(duration) = action.duration_seconds {
        if duration == 0 || duration > limits.maximum_duration_seconds {
            errors.push(error(
                ValidationErrorCode::DurationOutOfRange,
                path.clone(),
                format!(
                    "duration must be between 1 and {} seconds",
                    limits.maximum_duration_seconds
                ),
            ));
        }
    }
    if let Some(replacement) = &action.replacement {
        check_limit(
            errors,
            path.clone(),
            "replacement",
            replacement,
            limits.replacement_characters,
        );
        if action.action_type != PolicyActionType::ReplaceName {
            errors.push(error(
                ValidationErrorCode::InvalidReplacement,
                path,
                "only REPLACE_NAME accepts a replacement",
            ));
        } else if replacement.trim().is_empty() {
            errors.push(error(
                ValidationErrorCode::InvalidReplacement,
                path,
                "REPLACE_NAME replacement must not be empty",
            ));
        }
    }
}

fn check_limit(
    errors: &mut Vec<PolicyValidationError>,
    path: String,
    label: &str,
    value: &str,
    maximum: usize,
) {
    let actual = value.chars().count();
    if actual > maximum {
        errors.push(error(
            ValidationErrorCode::TextTooLong,
            path,
            format!("{label} is {actual} characters; maximum is {maximum}"),
        ));
    }
}

fn pattern_error_to_validation(
    rule: &PolicyRule,
    pattern: &RulePattern,
    parse_error: PatternError,
) -> PolicyValidationError {
    error(
        ValidationErrorCode::Pattern,
        pattern_path(rule, pattern),
        parse_error.to_string(),
    )
}

fn pattern_error(code: PatternErrorCode, pattern: &str) -> PatternError {
    PatternError {
        code,
        pattern: pattern.into(),
    }
}

fn contains_unsupported_syntax(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '+' | '^' | '$' | '\\'
        )
    })
}

fn error(
    code: ValidationErrorCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> PolicyValidationError {
    PolicyValidationError {
        code,
        path: path.into(),
        message: message.into(),
    }
}

fn rule_path(rule: &PolicyRule) -> String {
    format!("rules[id={}]", rule.id)
}

fn pattern_path(rule: &PolicyRule, pattern: &RulePattern) -> String {
    format!("{}.patterns[id={}]", rule_path(rule), pattern.id)
}

fn compare_validation_errors(
    left: &PolicyValidationError,
    right: &PolicyValidationError,
) -> Ordering {
    left.code
        .cmp(&right.code)
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.message.cmp(&right.message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn pattern(value: &str) -> RulePattern {
        RulePattern {
            id: Uuid::new_v4(),
            pattern: value.into(),
            pattern_type: classify_pattern(value).unwrap_or(WildcardPatternType::ExactWord),
        }
    }

    fn rule(name: &str, value: &str, action_type: PolicyActionType) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            name: name.into(),
            description: String::new(),
            enabled: true,
            custom_reason: None,
            created_by: "test".into(),
            patterns: vec![pattern(value)],
            surfaces: BTreeSet::from([super::super::model::Surface::MessageContent]),
            actions: vec![PolicyAction {
                id: Uuid::new_v4(),
                action_type,
                duration_seconds: match action_type {
                    PolicyActionType::LobbyBan
                    | PolicyActionType::Blacklist
                    | PolicyActionType::HubMute => Some(60),
                    _ => None,
                },
                replacement: None,
            }],
        }
    }

    fn policy(authority: Authority, rules: Vec<PolicyRule>) -> ContentPolicy {
        ContentPolicy {
            id: Uuid::new_v4(),
            scope: match authority {
                Authority::Global => super::super::model::PolicyScope::global(),
                Authority::Hub => super::super::model::PolicyScope::hub("hub"),
                Authority::Server => super::super::model::PolicyScope::server("server"),
            },
            enabled: true,
            version: 1,
            rules,
        }
    }

    #[test]
    fn parser_accepts_the_five_forms() {
        assert_eq!(classify_pattern("word"), Ok(WildcardPatternType::ExactWord));
        assert_eq!(classify_pattern("word*"), Ok(WildcardPatternType::Prefix));
        assert_eq!(classify_pattern("*word"), Ok(WildcardPatternType::Suffix));
        assert_eq!(
            classify_pattern("*word*"),
            Ok(WildcardPatternType::Contains)
        );
        assert_eq!(
            classify_pattern(" \"two words\" "),
            Ok(WildcardPatternType::Phrase)
        );
    }

    #[test]
    fn parser_rejects_empty_quotes_regex_and_internal_wildcards() {
        for value in [
            "",
            "   ",
            "\"\"",
            "\"one\"",
            "one two",
            "\"one two",
            "one two\"",
            "fo*o",
            "**",
            ".*word",
            "word.*",
            "word?",
            "word[one]",
        ] {
            assert!(parse_pattern(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn classification_is_atomic() {
        let mut valid = policy(
            Authority::Server,
            vec![rule("one", "word*", PolicyActionType::Block)],
        );
        assert!(validate_and_classify_policy(&mut valid, PolicyLimits::default()).is_ok());
        assert_eq!(
            valid.rules[0].patterns[0].pattern_type,
            WildcardPatternType::Prefix
        );

        let mut invalid = policy(
            Authority::Server,
            vec![rule("one", "bad pattern", PolicyActionType::Block)],
        );
        let before = invalid.rules[0].patterns[0].pattern_type;
        assert!(validate_and_classify_policy(&mut invalid, PolicyLimits::default()).is_err());
        assert_eq!(invalid.rules[0].patterns[0].pattern_type, before);
    }

    #[test]
    fn validation_enforces_presence_duplicates_and_rule_order_independence() {
        let first = rule("same", "word", PolicyActionType::Block);
        let second = rule("same", "word", PolicyActionType::Block);
        let policy_a = policy(Authority::Server, vec![first.clone(), second.clone()]);
        let policy_b = policy(Authority::Server, vec![second, first]);
        let errors_a = validate_policy(&policy_a, PolicyLimits::default()).unwrap_err();
        let errors_b = validate_policy(&policy_b, PolicyLimits::default()).unwrap_err();
        assert_eq!(errors_a.errors, errors_b.errors);

        let empty = policy(
            Authority::Server,
            vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "empty".into(),
                description: String::new(),
                enabled: false,
                custom_reason: None,
                created_by: String::new(),
                patterns: Vec::new(),
                surfaces: BTreeSet::new(),
                actions: Vec::new(),
            }],
        );
        let errors = validate_policy(&empty, PolicyLimits::default()).unwrap_err();
        assert!(
            errors
                .errors
                .iter()
                .any(|item| item.code == ValidationErrorCode::MissingPatterns)
        );
        assert!(
            errors
                .errors
                .iter()
                .any(|item| item.code == ValidationErrorCode::MissingSurfaces)
        );
        assert!(
            errors
                .errors
                .iter()
                .any(|item| item.code == ValidationErrorCode::MissingActions)
        );
    }

    #[test]
    fn authority_and_duration_rules_are_enforced() {
        assert!(
            validate_policy(
                &policy(
                    Authority::Global,
                    vec![rule("warn", "word", PolicyActionType::LobbyWarn)]
                ),
                PolicyLimits::default()
            )
            .is_ok()
        );
        assert!(
            validate_policy(
                &policy(
                    Authority::Hub,
                    vec![rule("mute", "word", PolicyActionType::HubMute)]
                ),
                PolicyLimits::default()
            )
            .is_ok()
        );
        assert!(
            validate_policy(
                &policy(
                    Authority::Server,
                    vec![rule("block", "word", PolicyActionType::Block)]
                ),
                PolicyLimits::default()
            )
            .is_ok()
        );

        for (authority, action) in [
            (Authority::Global, PolicyActionType::Log),
            (Authority::Global, PolicyActionType::HubBan),
            (Authority::Hub, PolicyActionType::LobbyWarn),
            (Authority::Server, PolicyActionType::HubWarn),
        ] {
            assert!(
                validate_policy(
                    &policy(authority, vec![rule("bad", "word", action)]),
                    PolicyLimits::default()
                )
                .is_err()
            );
        }

        let mut global = rule("ban", "word", PolicyActionType::LobbyBan);
        global.actions[0].duration_seconds = None;
        assert!(
            validate_policy(
                &policy(Authority::Global, vec![global]),
                PolicyLimits::default()
            )
            .is_err()
        );

        let mut hub = rule("ban", "word", PolicyActionType::HubBan);
        assert!(
            validate_policy(
                &policy(Authority::Hub, vec![hub.clone()]),
                PolicyLimits::default()
            )
            .is_ok()
        );
        hub.actions[0].duration_seconds = Some(60);
        assert!(
            validate_policy(&policy(Authority::Hub, vec![hub]), PolicyLimits::default()).is_err()
        );
    }
}
