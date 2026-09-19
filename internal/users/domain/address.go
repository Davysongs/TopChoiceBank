package domain

import (
	"strings"
	"unicode/utf8"
)

// iso3166Alpha2 contains all officially assigned ISO 3166-1 alpha-2 country codes.
var iso3166Alpha2 = map[string]struct{}{
	"AD": {}, "AE": {}, "AF": {}, "AG": {}, "AI": {}, "AL": {}, "AM": {}, "AO": {}, "AQ": {}, "AR": {},
	"AS": {}, "AT": {}, "AU": {}, "AW": {}, "AX": {}, "AZ": {}, "BA": {}, "BB": {}, "BD": {}, "BE": {},
	"BF": {}, "BG": {}, "BH": {}, "BI": {}, "BJ": {}, "BL": {}, "BM": {}, "BN": {}, "BO": {}, "BQ": {},
	"BR": {}, "BS": {}, "BT": {}, "BV": {}, "BW": {}, "BY": {}, "BZ": {}, "CA": {}, "CC": {}, "CD": {},
	"CF": {}, "CG": {}, "CH": {}, "CI": {}, "CK": {}, "CL": {}, "CM": {}, "CN": {}, "CO": {}, "CR": {},
	"CU": {}, "CV": {}, "CW": {}, "CX": {}, "CY": {}, "CZ": {}, "DE": {}, "DJ": {}, "DK": {}, "DM": {},
	"DO": {}, "DZ": {}, "EC": {}, "EE": {}, "EG": {}, "EH": {}, "ER": {}, "ES": {}, "ET": {}, "FI": {},
	"FJ": {}, "FK": {}, "FM": {}, "FO": {}, "FR": {}, "GA": {}, "GB": {}, "GD": {}, "GE": {}, "GF": {},
	"GG": {}, "GH": {}, "GI": {}, "GL": {}, "GM": {}, "GN": {}, "GP": {}, "GQ": {}, "GR": {}, "GS": {},
	"GT": {}, "GU": {}, "GW": {}, "GY": {}, "HK": {}, "HM": {}, "HN": {}, "HR": {}, "HT": {}, "HU": {},
	"ID": {}, "IE": {}, "IL": {}, "IM": {}, "IN": {}, "IO": {}, "IQ": {}, "IR": {}, "IS": {}, "IT": {},
	"JE": {}, "JM": {}, "JO": {}, "JP": {}, "KE": {}, "KG": {}, "KH": {}, "KI": {}, "KM": {}, "KN": {},
	"KP": {}, "KR": {}, "KW": {}, "KY": {}, "KZ": {}, "LA": {}, "LB": {}, "LC": {}, "LI": {}, "LK": {},
	"LR": {}, "LS": {}, "LT": {}, "LU": {}, "LV": {}, "LY": {}, "MA": {}, "MC": {}, "MD": {}, "ME": {},
	"MF": {}, "MG": {}, "MH": {}, "MK": {}, "ML": {}, "MM": {}, "MN": {}, "MO": {}, "MP": {}, "MQ": {},
	"MR": {}, "MS": {}, "MT": {}, "MU": {}, "MV": {}, "MW": {}, "MX": {}, "MY": {}, "MZ": {}, "NA": {},
	"NC": {}, "NE": {}, "NF": {}, "NG": {}, "NI": {}, "NL": {}, "NO": {}, "NP": {}, "NR": {}, "NU": {},
	"NZ": {}, "OM": {}, "PA": {}, "PE": {}, "PF": {}, "PG": {}, "PH": {}, "PK": {}, "PL": {}, "PM": {},
	"PN": {}, "PR": {}, "PS": {}, "PT": {}, "PW": {}, "PY": {}, "QA": {}, "RE": {}, "RO": {}, "RS": {},
	"RU": {}, "RW": {}, "SA": {}, "SB": {}, "SC": {}, "SD": {}, "SE": {}, "SG": {}, "SH": {}, "SI": {},
	"SJ": {}, "SK": {}, "SL": {}, "SM": {}, "SN": {}, "SO": {}, "SR": {}, "SS": {}, "ST": {}, "SV": {},
	"SX": {}, "SY": {}, "SZ": {}, "TC": {}, "TD": {}, "TF": {}, "TG": {}, "TH": {}, "TJ": {}, "TK": {},
	"TL": {}, "TM": {}, "TN": {}, "TO": {}, "TR": {}, "TT": {}, "TV": {}, "TW": {}, "TZ": {}, "UA": {},
	"UG": {}, "UM": {}, "US": {}, "UY": {}, "UZ": {}, "VA": {}, "VC": {}, "VE": {}, "VG": {}, "VI": {},
	"VN": {}, "VU": {}, "WF": {}, "WS": {}, "YE": {}, "YT": {}, "ZA": {}, "ZM": {}, "ZW": {},
}

// Address represents a validated postal address with an ISO 3166-1 alpha-2 country code.
type Address struct {
	line1       string
	line2       string
	city        string
	region      string
	postalCode  string
	countryCode string
}

// NewAddress constructs and validates an Address value object.
func NewAddress(line1, line2, city, region, postalCode, countryCode string) (Address, error) {
	trimmedLine1 := strings.TrimSpace(line1)
	trimmedLine2 := strings.TrimSpace(line2)
	trimmedCity := strings.TrimSpace(city)
	trimmedRegion := strings.TrimSpace(region)
	trimmedPostalCode := strings.TrimSpace(postalCode)
	trimmedCountry := strings.ToUpper(strings.TrimSpace(countryCode))

	if trimmedLine1 == "" {
		return Address{}, ErrEmptyAddressLine1
	}
	if utf8.RuneCountInString(trimmedLine1) > 255 {
		return Address{}, ErrAddressLine1TooLong
	}

	if utf8.RuneCountInString(trimmedLine2) > 255 {
		return Address{}, ErrAddressLine2TooLong
	}

	if trimmedCity == "" {
		return Address{}, ErrEmptyCity
	}
	if utf8.RuneCountInString(trimmedCity) > 100 {
		return Address{}, ErrCityTooLong
	}

	if utf8.RuneCountInString(trimmedRegion) > 100 {
		return Address{}, ErrRegionTooLong
	}

	if utf8.RuneCountInString(trimmedPostalCode) > 20 {
		return Address{}, ErrPostalCodeTooLong
	}

	if _, ok := iso3166Alpha2[trimmedCountry]; !ok {
		return Address{}, ErrInvalidCountryCode
	}

	return Address{
		line1:       trimmedLine1,
		line2:       trimmedLine2,
		city:        trimmedCity,
		region:      trimmedRegion,
		postalCode:  trimmedPostalCode,
		countryCode: trimmedCountry,
	}, nil
}

// Line1 returns the primary address line.
func (a Address) Line1() string {
	return a.line1
}

// Line2 returns the optional secondary address line.
func (a Address) Line2() string {
	return a.line2
}

// City returns the city or town.
func (a Address) City() string {
	return a.city
}

// Region returns the optional state, province, or region.
func (a Address) Region() string {
	return a.region
}

// PostalCode returns the optional postal or ZIP code.
func (a Address) PostalCode() string {
	return a.postalCode
}

// CountryCode returns the 2-letter ISO 3166-1 alpha-2 country code.
func (a Address) CountryCode() string {
	return a.countryCode
}

// Formatted returns a single-line summary of the address.
func (a Address) Formatted() string {
	var parts []string
	parts = append(parts, a.line1)
	if a.line2 != "" {
		parts = append(parts, a.line2)
	}
	parts = append(parts, a.city)
	if a.region != "" {
		parts = append(parts, a.region)
	}
	if a.postalCode != "" {
		parts = append(parts, a.postalCode)
	}
	parts = append(parts, a.countryCode)
	return strings.Join(parts, ", ")
}

// Equals checks value equality between two Address instances.
func (a Address) Equals(other Address) bool {
	return a.line1 == other.line1 &&
		a.line2 == other.line2 &&
		a.city == other.city &&
		a.region == other.region &&
		a.postalCode == other.postalCode &&
		a.countryCode == other.countryCode
}

// IsZero returns true if the Address is an uninitialized zero value.
func (a Address) IsZero() bool {
	return a.line1 == "" && a.city == "" && a.countryCode == ""
}

