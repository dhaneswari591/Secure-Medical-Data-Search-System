-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Aug 27, 2023 at 09:59 AM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `database`
--

-- --------------------------------------------------------

--
-- Table structure for table `tbl_countries`
--

CREATE TABLE `tbl_countries` (
  `countrycode` char(3) NOT NULL,
  `countryname` varchar(200) NOT NULL,
  `code` char(2) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

--
-- Dumping data for table `tbl_countries`
--

INSERT INTO `tbl_countries` (`countrycode`, `countryname`, `code`) VALUES
('ABW', 'Aruba', 'AW'),
('AFG', 'Afghanistan', 'AF'),
('AGO', 'Angola', 'AO'),
('AIA', 'Anguilla', 'AI'),
('ALA', 'Åland', 'AX'),
('ALB', 'Albania', 'AL'),
('AND', 'Andorra', 'AD'),
('ARE', 'United Arab Emirates', 'AE'),
('ARG', 'Argentina', 'AR'),
('ARM', 'Armenia', 'AM'),
('ASM', 'American Samoa', 'AS'),
('ATA', 'Antarctica', 'AQ'),
('ATF', 'French Southern Territories', 'TF'),
('ATG', 'Antigua and Barbuda', 'AG'),
('AUS', 'Australia', 'AU'),
('AUT', 'Austria', 'AT'),
('AZE', 'Azerbaijan', 'AZ'),
('BDI', 'Burundi', 'BI'),
('BEL', 'Belgium', 'BE'),
('BEN', 'Benin', 'BJ'),
('BES', 'Bonaire', 'BQ'),
('BFA', 'Burkina Faso', 'BF'),
('BGD', 'Bangladesh', 'BD'),
('BGR', 'Bulgaria', 'BG'),
('BHR', 'Bahrain', 'BH'),
('BHS', 'Bahamas', 'BS'),
('BIH', 'Bosnia and Herzegovina', 'BA'),
('BLM', 'Saint Barthélemy', 'BL'),
('BLR', 'Belarus', 'BY'),
('BLZ', 'Belize', 'BZ'),
('BMU', 'Bermuda', 'BM'),
('BOL', 'Bolivia', 'BO'),
('BRA', 'Brazil', 'BR'),
('BRB', 'Barbados', 'BB'),
('BRN', 'Brunei', 'BN'),
('BTN', 'Bhutan', 'BT'),
('BVT', 'Bouvet Island', 'BV'),
('BWA', 'Botswana', 'BW'),
('CAF', 'Central African Republic', 'CF'),
('CAN', 'Canada', 'CA'),
('CCK', 'Cocos [Keeling] Islands', 'CC'),
('CHE', 'Switzerland', 'CH'),
('CHL', 'Chile', 'CL'),
('CHN', 'China', 'CN'),
('CIV', 'Ivory Coast', 'CI'),
('CMR', 'Cameroon', 'CM'),
('COD', 'Democratic Republic of the Congo', 'CD'),
('COG', 'Republic of the Congo', 'CG'),
('COK', 'Cook Islands', 'CK'),
('COL', 'Colombia', 'CO'),
('COM', 'Comoros', 'KM'),
('CPV', 'Cape Verde', 'CV'),
('CRI', 'Costa Rica', 'CR'),
('CUB', 'Cuba', 'CU'),
('CUW', 'Curacao', 'CW'),
('CXR', 'Christmas Island', 'CX'),
('CYM', 'Cayman Islands', 'KY'),
('CYP', 'Cyprus', 'CY'),
('CZE', 'Czech Republic', 'CZ'),
('DEU', 'Germany', 'DE'),
('DJI', 'Djibouti', 'DJ'),
('DMA', 'Dominica', 'DM'),
('DNK', 'Denmark', 'DK'),
('DOM', 'Dominican Republic', 'DO'),
('DZA', 'Algeria', 'DZ'),
('ECU', 'Ecuador', 'EC'),
('EGY', 'Egypt', 'EG'),
('ERI', 'Eritrea', 'ER'),
('ESH', 'Western Sahara', 'EH'),
('ESP', 'Spain', 'ES'),
('EST', 'Estonia', 'EE'),
('ETH', 'Ethiopia', 'ET'),
('FIN', 'Finland', 'FI'),
('FJI', 'Fiji', 'FJ'),
('FLK', 'Falkland Islands', 'FK'),
('FRA', 'France', 'FR'),
('FRO', 'Faroe Islands', 'FO'),
('FSM', 'Micronesia', 'FM'),
('GAB', 'Gabon', 'GA'),
('GBR', 'United Kingdom', 'GB'),
('GEO', 'Georgia', 'GE'),
('GGY', 'Guernsey', 'GG'),
('GHA', 'Ghana', 'GH'),
('GIB', 'Gibraltar', 'GI'),
('GIN', 'Guinea', 'GN'),
('GLP', 'Guadeloupe', 'GP'),
('GMB', 'Gambia', 'GM'),
('GNB', 'Guinea-Bissau', 'GW'),
('GNQ', 'Equatorial Guinea', 'GQ'),
('GRC', 'Greece', 'GR'),
('GRD', 'Grenada', 'GD'),
('GRL', 'Greenland', 'GL'),
('GTM', 'Guatemala', 'GT'),
('GUF', 'French Guiana', 'GF'),
('GUM', 'Guam', 'GU'),
('GUY', 'Guyana', 'GY'),
('HKG', 'Hong Kong', 'HK'),
('HMD', 'Heard Island and McDonald Islands', 'HM'),
('HND', 'Honduras', 'HN'),
('HRV', 'Croatia', 'HR'),
('HTI', 'Haiti', 'HT'),
('HUN', 'Hungary', 'HU'),
('IDN', 'Indonesia', 'ID'),
('IMN', 'Isle of Man', 'IM'),
('IND', 'India', 'IN'),
('IOT', 'British Indian Ocean Territory', 'IO'),
('IRL', 'Ireland', 'IE'),
('IRN', 'Iran', 'IR'),
('IRQ', 'Iraq', 'IQ'),
('ISL', 'Iceland', 'IS'),
('ISR', 'Israel', 'IL'),
('ITA', 'Italy', 'IT'),
('JAM', 'Jamaica', 'JM'),
('JEY', 'Jersey', 'JE'),
('JOR', 'Jordan', 'JO'),
('JPN', 'Japan', 'JP'),
('KAZ', 'Kazakhstan', 'KZ'),
('KEN', 'Kenya', 'KE'),
('KGZ', 'Kyrgyzstan', 'KG'),
('KHM', 'Cambodia', 'KH'),
('KIR', 'Kiribati', 'KI'),
('KNA', 'Saint Kitts and Nevis', 'KN'),
('KOR', 'South Korea', 'KR'),
('KWT', 'Kuwait', 'KW'),
('LAO', 'Laos', 'LA'),
('LBN', 'Lebanon', 'LB'),
('LBR', 'Liberia', 'LR'),
('LBY', 'Libya', 'LY'),
('LCA', 'Saint Lucia', 'LC'),
('LIE', 'Liechtenstein', 'LI'),
('LKA', 'Sri Lanka', 'LK'),
('LSO', 'Lesotho', 'LS'),
('LTU', 'Lithuania', 'LT'),
('LUX', 'Luxembourg', 'LU'),
('LVA', 'Latvia', 'LV'),
('MAC', 'Macao', 'MO'),
('MAF', 'Saint Martin', 'MF'),
('MAR', 'Morocco', 'MA'),
('MCO', 'Monaco', 'MC'),
('MDA', 'Moldova', 'MD'),
('MDG', 'Madagascar', 'MG'),
('MDV', 'Maldives', 'MV'),
('MEX', 'Mexico', 'MX'),
('MHL', 'Marshall Islands', 'MH'),
('MKD', 'Macedonia', 'MK'),
('MLI', 'Mali', 'ML'),
('MLT', 'Malta', 'MT'),
('MMR', 'Myanmar [Burma]', 'MM'),
('MNE', 'Montenegro', 'ME'),
('MNG', 'Mongolia', 'MN'),
('MNP', 'Northern Mariana Islands', 'MP'),
('MOZ', 'Mozambique', 'MZ'),
('MRT', 'Mauritania', 'MR'),
('MSR', 'Montserrat', 'MS'),
('MTQ', 'Martinique', 'MQ'),
('MUS', 'Mauritius', 'MU'),
('MWI', 'Malawi', 'MW'),
('MYS', 'Malaysia', 'MY'),
('MYT', 'Mayotte', 'YT'),
('NAM', 'Namibia', 'NA'),
('NCL', 'New Caledonia', 'NC'),
('NER', 'Niger', 'NE'),
('NFK', 'Norfolk Island', 'NF'),
('NGA', 'Nigeria', 'NG'),
('NIC', 'Nicaragua', 'NI'),
('NIU', 'Niue', 'NU'),
('NLD', 'Netherlands', 'NL'),
('NOR', 'Norway', 'NO'),
('NPL', 'Nepal', 'NP'),
('NRU', 'Nauru', 'NR'),
('NZL', 'New Zealand', 'NZ'),
('OMN', 'Oman', 'OM'),
('PAK', 'Pakistan', 'PK'),
('PAN', 'Panama', 'PA'),
('PCN', 'Pitcairn Islands', 'PN'),
('PER', 'Peru', 'PE'),
('PHL', 'Philippines', 'PH'),
('PLW', 'Palau', 'PW'),
('PNG', 'Papua New Guinea', 'PG'),
('POL', 'Poland', 'PL'),
('PRI', 'Puerto Rico', 'PR'),
('PRK', 'North Korea', 'KP'),
('PRT', 'Portugal', 'PT'),
('PRY', 'Paraguay', 'PY'),
('PSE', 'Palestine', 'PS'),
('PYF', 'French Polynesia', 'PF'),
('QAT', 'Qatar', 'QA'),
('REU', 'Réunion', 'RE'),
('ROU', 'Romania', 'RO'),
('RUS', 'Russia', 'RU'),
('RWA', 'Rwanda', 'RW'),
('SAU', 'Saudi Arabia', 'SA'),
('SDN', 'Sudan', 'SD'),
('SEN', 'Senegal', 'SN'),
('SGP', 'Singapore', 'SG'),
('SGS', 'South Georgia and the South Sandwich Islands', 'GS'),
('SHN', 'Saint Helena', 'SH'),
('SJM', 'Svalbard and Jan Mayen', 'SJ'),
('SLB', 'Solomon Islands', 'SB'),
('SLE', 'Sierra Leone', 'SL'),
('SLV', 'El Salvador', 'SV'),
('SMR', 'San Marino', 'SM'),
('SOM', 'Somalia', 'SO'),
('SPM', 'Saint Pierre and Miquelon', 'PM'),
('SRB', 'Serbia', 'RS'),
('SSD', 'South Sudan', 'SS'),
('STP', 'São Tomé and Príncipe', 'ST'),
('SUR', 'Suriname', 'SR'),
('SVK', 'Slovakia', 'SK'),
('SVN', 'Slovenia', 'SI'),
('SWE', 'Sweden', 'SE'),
('SWZ', 'Swaziland', 'SZ'),
('SXM', 'Sint Maarten', 'SX'),
('SYC', 'Seychelles', 'SC'),
('SYR', 'Syria', 'SY'),
('TCA', 'Turks and Caicos Islands', 'TC'),
('TCD', 'Chad', 'TD'),
('TGO', 'Togo', 'TG'),
('THA', 'Thailand', 'TH'),
('TJK', 'Tajikistan', 'TJ'),
('TKL', 'Tokelau', 'TK'),
('TKM', 'Turkmenistan', 'TM'),
('TLS', 'East Timor', 'TL'),
('TON', 'Tonga', 'TO'),
('TTO', 'Trinidad and Tobago', 'TT'),
('TUN', 'Tunisia', 'TN'),
('TUR', 'Turkey', 'TR'),
('TUV', 'Tuvalu', 'TV'),
('TWN', 'Taiwan', 'TW'),
('TZA', 'Tanzania', 'TZ'),
('UGA', 'Uganda', 'UG'),
('UKR', 'Ukraine', 'UA'),
('UMI', 'U.S. Minor Outlying Islands', 'UM'),
('URY', 'Uruguay', 'UY'),
('USA', 'United States', 'US'),
('UZB', 'Uzbekistan', 'UZ'),
('VAT', 'Vatican City', 'VA'),
('VCT', 'Saint Vincent and the Grenadines', 'VC'),
('VEN', 'Venezuela', 'VE'),
('VGB', 'British Virgin Islands', 'VG'),
('VIR', 'U.S. Virgin Islands', 'VI'),
('VNM', 'Vietnam', 'VN'),
('VUT', 'Vanuatu', 'VU'),
('WLF', 'Wallis and Futuna', 'WF'),
('WSM', 'Samoa', 'WS'),
('XKX', 'Kosovo', 'XK'),
('YEM', 'Yemen', 'YE'),
('ZAF', 'South Africa', 'ZA'),
('ZMB', 'Zambia', 'ZM'),
('ZWE', 'Zimbabwe', 'ZW');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_insuarance_category`
--

CREATE TABLE `tbl_insuarance_category` (
  `id` int(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `status` int(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_insuarance_policy`
--

CREATE TABLE `tbl_insuarance_policy` (
  `id` int(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `category` int(10) NOT NULL,
  `sub_category` int(10) NOT NULL,
  `sum_assured` double NOT NULL,
  `premium` double NOT NULL,
  `tenture` int(10) NOT NULL,
  `status` int(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_insuarance_sub_category`
--

CREATE TABLE `tbl_insuarance_sub_category` (
  `id` int(10) NOT NULL,
  `category` int(10) NOT NULL,
  `name` varchar(100) NOT NULL,
  `status` int(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_login_sessions`
--

CREATE TABLE `tbl_login_sessions` (
  `sess_id` varchar(70) NOT NULL,
  `sess_ip` varchar(70) NOT NULL,
  `account` int(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_notifications`
--

CREATE TABLE `tbl_notifications` (
  `id` int(70) NOT NULL,
  `user` int(70) NOT NULL,
  `notification` varchar(255) NOT NULL,
  `ticket` int(70) DEFAULT NULL,
  `status` int(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_organization`
--

CREATE TABLE `tbl_organization` (
  `name` varchar(100) NOT NULL DEFAULT 'EOK Financers',
  `email` varchar(60) NOT NULL DEFAULT 'gracekway76@gmail.com',
  `phone` varchar(60) NOT NULL DEFAULT '+255695426745',
  `phone_alt` varchar(60) DEFAULT '+255736938643',
  `city` varchar(60) NOT NULL DEFAULT 'Dar es Salaam',
  `street` varchar(100) NOT NULL DEFAULT 'Kimara Korogwe',
  `country` varchar(70) NOT NULL DEFAULT 'Tanzania',
  `currency` varchar(6) NOT NULL DEFAULT 'Tsh',
  `timezone` varchar(60) NOT NULL DEFAULT 'Africa/Dar_es_Salaam',
  `logo` varchar(60) NOT NULL DEFAULT 'default.png',
  `iso` varchar(5) NOT NULL DEFAULT 'TZS',
  `side_bar` varchar(70) NOT NULL DEFAULT 'sidebar-light',
  `header` varchar(70) NOT NULL DEFAULT 'header_style_light',
  `sidebar_pos` varchar(70) NOT NULL DEFAULT 'sidebar_pos_left',
  `sidebar_min` varchar(70) NOT NULL DEFAULT 'sidebar_mini_off',
  `main_content` varchar(70) NOT NULL DEFAULT 'main-content-boxed',
  `page_header` varchar(70) NOT NULL DEFAULT 'page-header-fixed',
  `color_theme` varchar(70) NOT NULL DEFAULT 'bg-header-dark'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_organization`
--

INSERT INTO `tbl_organization` (`name`, `email`, `phone`, `phone_alt`, `city`, `street`, `country`, `currency`, `timezone`, `logo`, `iso`, `side_bar`, `header`, `sidebar_pos`, `sidebar_min`, `main_content`, `page_header`, `color_theme`) VALUES
('Wise-Insurance Agency', 'bmashauri704@gmail.com', '+255695426745', '+255736938643', 'Dar es Salaam', 'Pugu Kichangani', 'Tanzania', 'Tsh', 'Africa/Dar_es_Salaam', 'logo_1693120817.png', 'TZS', 'sidebar-dark', 'page-header-dark', 'sidebar-l', '', 'main-content-narrowed', 'page-header-fixed', 'xwork.min-5.7.css');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_policy_applications`
--

CREATE TABLE `tbl_policy_applications` (
  `id` int(70) NOT NULL,
  `member_id` int(10) NOT NULL,
  `policy_id` int(10) NOT NULL,
  `sum_assured` double NOT NULL,
  `premium` double NOT NULL,
  `tenture` int(10) NOT NULL,
  `active_date` date DEFAULT NULL,
  `approved_by` int(10) DEFAULT NULL,
  `status` int(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_smtp`
--

CREATE TABLE `tbl_smtp` (
  `server` varchar(50) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `port` varchar(255) NOT NULL,
  `security` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_smtp`
--

INSERT INTO `tbl_smtp` (`server`, `username`, `password`, `port`, `security`) VALUES
('smtp server', 'smtp username', 'smtp password', '587', 'tls');

-- --------------------------------------------------------

--
-- Table structure for table `tbl_tickets`
--

CREATE TABLE `tbl_tickets` (
  `id` int(70) NOT NULL,
  `member_id` int(10) NOT NULL,
  `category` int(10) NOT NULL,
  `subject` varchar(100) NOT NULL,
  `ticket_description` longtext NOT NULL,
  `open_date` date NOT NULL,
  `assigned_to` int(10) DEFAULT NULL,
  `close_date` date DEFAULT NULL,
  `status` int(1) NOT NULL DEFAULT 0 COMMENT '0 = Submitted, 1 = Pending, 2 = Closed',
  `remark` longtext DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_tickets_replies`
--

CREATE TABLE `tbl_tickets_replies` (
  `id` int(70) NOT NULL,
  `ticket` int(70) NOT NULL,
  `sender` int(10) NOT NULL,
  `reply` longtext NOT NULL,
  `rep_date` varchar(70) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_ticket_categories`
--

CREATE TABLE `tbl_ticket_categories` (
  `id` int(10) NOT NULL,
  `name` varchar(70) NOT NULL,
  `status` int(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tbl_timezones`
--

CREATE TABLE `tbl_timezones` (
  `id` int(255) NOT NULL,
  `continet` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `timezone` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `pid` int(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `tbl_timezones`
--

INSERT INTO `tbl_timezones` (`id`, `continet`, `timezone`, `pid`) VALUES
(1, 'Africa', 'Africa/Abidjan', 1),
(2, 'Africa', 'Africa/Addis_Ababa', 2),
(3, 'Africa', 'Africa/Accra', 3),
(4, 'Africa', 'Africa/Algiers', 4),
(5, 'Africa', 'Africa/Asmara', 5),
(6, 'Africa', 'Africa/Bamako', 6),
(7, 'Africa', 'Africa/Bangui', 7),
(8, 'Africa', 'Africa/Banjul', 8),
(9, 'Africa', 'Africa/Bissau', 9),
(10, 'Africa', 'Africa/Blantyre', 10),
(11, 'Africa', 'Africa/Brazzaville', 11),
(12, 'Africa', 'Africa/Bujumbura', 12),
(13, 'Africa', 'Africa/Cairo', 13),
(14, 'Africa', 'Africa/Casablanca', 14),
(15, 'Africa', 'Africa/Ceuta', 15),
(16, 'Africa', 'Africa/Conakry', 16),
(17, 'Africa', 'Africa/Dakar', 17),
(18, 'Africa', 'Africa/Dar_es_Salaam', 18),
(19, 'Africa', 'Africa/Djibouti', 19),
(20, 'Africa', 'Africa/Douala', 20),
(21, 'Africa', 'Africa/El_Aaiun', 21),
(22, 'Africa', 'Africa/Freetown', 22),
(23, 'Africa', 'Africa/Gaborone', 23),
(24, 'Africa', 'Africa/Harare', 24),
(25, 'Africa', 'Africa/Johannesburg', 25),
(26, 'Africa', 'Africa/Juba', 26),
(27, 'Africa', 'Africa/Kampala', 27),
(28, 'Africa', 'Africa/Khartoum', 28),
(29, 'Africa', 'Africa/Kigali', 29),
(30, 'Africa', 'Africa/Kinshasa', 30),
(31, 'Africa', 'Africa/Lagos', 31),
(32, 'Africa', 'Africa/Libreville', 32),
(33, 'Africa', 'Africa/Lome', 33),
(34, 'Africa', 'Africa/Luanda', 34),
(35, 'Africa', 'Africa/Lubumbashi', 35),
(36, 'Africa', 'Africa/Lusaka', 36),
(37, 'Africa', 'Africa/Malabo', 37),
(38, 'Africa', 'Africa/Maputo', 38),
(39, 'Africa', 'Africa/Maseru', 39),
(40, 'Africa', 'Africa/Mbabane', 40),
(41, 'Africa', 'Africa/Mogadishu', 41),
(42, 'Africa', 'Africa/Monrovia', 42),
(43, 'Africa', 'Africa/Nairobi', 43),
(44, 'Africa', 'Africa/Ndjamena', 44),
(45, 'Africa', 'Africa/Niamey', 45),
(46, 'Africa', 'Africa/Nouakchott', 46),
(47, 'Africa', 'Africa/Ouagadougou', 47),
(48, 'Africa', 'Africa/Porto-Novo', 48),
(49, 'Africa', 'Africa/Sao_Tome', 49),
(50, 'Africa', 'Africa/Tripoli', 50),
(51, 'Africa', 'Africa/Tunis', 51),
(52, 'Africa', 'Africa/Windhoek', 52),
(53, 'Antarctica', 'Antarctica/Casey', 53),
(54, 'Antarctica', 'Antarctica/Davis', 54),
(55, 'Antarctica', 'Antarctica/DumontDUrville', 55),
(56, 'Antarctica', 'Antarctica/Macquarie', 56),
(57, 'Antarctica', 'Antarctica/Mawson', 57),
(58, 'Antarctica', 'Antarctica/McMurdo', 58),
(59, 'Antarctica', 'Antarctica/Palmer', 59),
(60, 'Antarctica', 'Antarctica/Rothera', 60),
(61, 'Antarctica', 'Antarctica/Syowa', 61),
(62, 'Antarctica', 'Antarctica/Troll', 62),
(63, 'Antarctica', 'Antarctica/Vostok', 63),
(64, 'Arctic', 'Arctic/Longyearbyen', 64),
(65, 'Australia', 'Australia/Adelaide', 65),
(66, 'Australia', 'Australia/Brisbane', 66),
(67, 'Australia', 'Australia/Broken_Hill', 67),
(68, 'Australia', 'Australia/Currie', 68),
(69, 'Australia', 'Australia/Darwin', 69),
(70, 'Australia', 'Australia/Eucla', 70),
(71, 'Australia', 'Australia/Hobart', 71),
(72, 'Australia', 'Australia/Lindeman', 72),
(73, 'Australia', 'Australia/Lord_Howe', 73),
(74, 'Australia', 'Australia/Melbourne', 74),
(75, 'Australia', 'Australia/Perth', 75),
(76, 'Australia', 'Australia/Sydney', 76),
(77, 'Atlantic', 'Atlantic/Azores', 77),
(78, 'Atlantic', 'Atlantic/Bermuda', 78),
(79, 'Atlantic', 'Atlantic/Canary', 79),
(80, 'Atlantic', 'Atlantic/Cape_Verde', 80),
(81, 'Atlantic', 'Atlantic/Faroe', 81),
(82, 'Atlantic', 'Atlantic/Madeira', 82),
(83, 'Atlantic', 'Atlantic/Reykjavik', 83),
(84, 'Atlantic', 'Atlantic/South_Georgia', 84),
(85, 'Atlantic', 'Atlantic/St_Helena', 85),
(86, 'Atlantic', 'Atlantic/Stanley', 86),
(87, 'Indian', 'Indian/Antananarivo', 87),
(88, 'Indian', 'Indian/Chagos', 88),
(89, 'Indian', 'Indian/Christmas', 89),
(90, 'Indian', 'Indian/Cocos', 90),
(91, 'Indian', 'Indian/Comoro', 91),
(92, 'Indian', 'Indian/Kerguelen', 92),
(93, 'Indian', 'Indian/Mahe', 93),
(94, 'Indian', 'Indian/Maldives', 94),
(95, 'Indian', 'Indian/Mauritius', 95),
(96, 'Indian', 'Indian/Mayotte', 96),
(97, 'Indian', 'Indian/Reunion', 97),
(98, 'Pacific', 'Pacific/Apia', 98),
(99, 'Pacific', 'Pacific/Auckland', 99),
(100, 'Pacific', 'Pacific/Bougainville', 100),
(101, 'Pacific', 'Pacific/Chatham', 101),
(102, 'Pacific', 'Pacific/Chuuk', 102),
(103, 'Pacific', 'Pacific/Easter', 103),
(104, 'Pacific', 'Pacific/Efate', 104),
(105, 'Pacific', 'Pacific/Enderbury', 105),
(106, 'Pacific', 'Pacific/Fakaofo', 106),
(107, 'Pacific', 'Pacific/Fiji', 107),
(108, 'Pacific', 'Pacific/Funafuti', 108),
(109, 'Pacific', 'Pacific/Galapagos', 109),
(110, 'Pacific', 'Pacific/Gambier', 110),
(111, 'Pacific', 'Pacific/Guadalcanal', 111),
(112, 'Pacific', 'Pacific/Guam', 112),
(113, 'Pacific', 'Pacific/Honolulu', 113),
(114, 'Pacific', 'Pacific/Kiritimati', 114),
(115, 'Pacific', 'Pacific/Kosrae', 115),
(116, 'Pacific', 'Pacific/Kwajalein', 116),
(117, 'Pacific', 'Pacific/Majuro', 117),
(118, 'Pacific', 'Pacific/Marquesas', 118),
(119, 'Pacific', 'Pacific/Midway', 119),
(120, 'Pacific', 'Pacific/Nauru', 120),
(121, 'Pacific', 'Pacific/Niue', 121),
(122, 'Pacific', 'Pacific/Norfolk', 122),
(123, 'Pacific', 'Pacific/Noumea', 123),
(124, 'Pacific', 'Pacific/Pago_Pago', 124),
(125, 'Pacific', 'Pacific/Palau', 125),
(126, 'Pacific', 'Pacific/Pitcairn', 126),
(127, 'Pacific', 'Pacific/Pohnpei', 127),
(128, 'Pacific', 'Pacific/Port_Moresby', 128),
(129, 'Pacific', 'Pacific/Rarotonga', 129),
(130, 'Pacific', 'Pacific/Saipan', 130),
(131, 'Pacific', 'Pacific/Tahiti', 131),
(132, 'Pacific', 'Pacific/Tarawa', 132),
(133, 'Pacific', 'Pacific/Tongatapu', 133),
(134, 'Pacific', 'Pacific/Wake', 134),
(135, 'Pacific', 'Pacific/Wallis', 135),
(136, 'Europe', 'Europe/Amsterdam', 136),
(137, 'Europe', 'Europe/Andorra', 137),
(138, 'Europe', 'Europe/Astrakhan', 138),
(139, 'Europe', 'Europe/Athens', 139),
(140, 'Europe', 'Europe/Belgrade', 140),
(141, 'Europe', 'Europe/Berlin', 141),
(142, 'Europe', 'Europe/Bratislava', 142),
(143, 'Europe', 'Europe/Brussels', 143),
(144, 'Europe', 'Europe/Bucharest', 144),
(145, 'Europe', 'Europe/Budapest', 145),
(146, 'Europe', 'Europe/Busingen', 146),
(147, 'Europe', 'Europe/Chisinau', 147),
(148, 'Europe', 'Europe/Copenhagen', 148),
(149, 'Europe', 'Europe/Dublin', 149),
(150, 'Europe', 'Europe/Gibraltar', 150),
(151, 'Europe', 'Europe/Guernsey', 151),
(152, 'Europe', 'Europe/Helsinki', 152),
(153, 'Europe', 'Europe/Isle_of_Man', 153),
(154, 'Europe', 'Europe/Istanbul', 154),
(155, 'Europe', 'Europe/Jersey', 155),
(156, 'Europe', 'Europe/Kaliningrad', 156),
(157, 'Europe', 'Europe/Kiev', 157),
(158, 'Europe', 'Europe/Kirov', 158),
(159, 'Europe', 'Europe/Lisbon', 159),
(160, 'Europe', 'Europe/Ljubljana', 160),
(161, 'Europe', 'Europe/London', 161),
(162, 'Europe', 'Europe/Luxembourg', 162),
(163, 'Europe', 'Europe/Madrid', 163),
(164, 'Europe', 'Europe/Malta', 164),
(165, 'Europe', 'Europe/Mariehamn', 165),
(166, 'Europe', 'Europe/Minsk', 166),
(167, 'Europe', 'Europe/Monaco', 167),
(168, 'Europe', 'Europe/Moscow', 168),
(169, 'Europe', 'Europe/Oslo', 169),
(170, 'Europe', 'Europe/Paris', 170),
(171, 'Europe', 'Europe/Podgorica', 171),
(172, 'Europe', 'Europe/Prague', 172),
(173, 'Europe', 'Europe/Riga', 173),
(174, 'Europe', 'Europe/Rome', 174),
(175, 'Europe', 'Europe/Samara', 175),
(176, 'Europe', 'Europe/San_Marino', 176),
(177, 'Europe', 'Europe/Sarajevo', 177),
(178, 'Europe', 'Europe/Saratov', 178),
(179, 'Europe', 'Europe/Simferopol', 179),
(180, 'Europe', 'Europe/Skopje', 180),
(181, 'Europe', 'Europe/Sofia', 181),
(182, 'Europe', 'Europe/Stockholm', 182),
(183, 'Europe', 'Europe/Tallinn', 183),
(184, 'Europe', 'Europe/Tirane', 184),
(185, 'Europe', 'Europe/Ulyanovsk', 185),
(186, 'Europe', 'Europe/Uzhgorod', 186),
(187, 'Europe', 'Europe/Vaduz', 187),
(188, 'Europe', 'Europe/Vatican', 188),
(189, 'Europe', 'Europe/Vienna', 189),
(190, 'Europe', 'Europe/Vilnius', 190),
(191, 'Europe', 'Europe/Volgograd', 191),
(192, 'Europe', 'Europe/Warsaw', 192),
(193, 'Europe', 'Europe/Zagreb', 193),
(194, 'Europe', 'Europe/Zaporozhye', 194),
(195, 'Europe', 'Europe/Zurich', 195),
(196, 'Asia', 'Asia/Aden', 196),
(197, 'Asia', 'Asia/Almaty', 197),
(198, 'Asia', 'Asia/Amman', 198),
(199, 'Asia', 'Asia/Anadyr', 199),
(200, 'Asia', 'Asia/Aqtau', 200),
(201, 'Asia', 'Asia/Aqtobe', 201),
(202, 'Asia', 'Asia/Ashgabat', 202),
(203, 'Asia', 'Asia/Atyrau', 203),
(204, 'Asia', 'Asia/Baghdad', 204),
(205, 'Asia', 'Asia/Bahrain', 205),
(206, 'Asia', 'Asia/Baku', 206),
(207, 'Asia', 'Asia/Bangkok', 207),
(208, 'Asia', 'Asia/Barnaul', 208),
(209, 'Asia', 'Asia/Beirut', 209),
(210, 'Asia', 'Asia/Bishkek', 210),
(211, 'Asia', 'Asia/Brunei', 211),
(212, 'Asia', 'Asia/Chita', 212),
(213, 'Asia', 'Asia/Choibalsan', 213),
(214, 'Asia', 'Asia/Colombo', 214),
(215, 'Asia', 'Asia/Damascus', 215),
(216, 'Asia', 'Asia/Dhaka', 216),
(217, 'Asia', 'Asia/Dili', 217),
(218, 'Asia', 'Asia/Dubai', 218),
(219, 'Asia', 'Asia/Dushanbe', 219),
(220, 'Asia', 'Asia/Famagusta', 220),
(221, 'Asia', 'Asia/Gaza', 221),
(222, 'Asia', 'Asia/Hebron', 222),
(223, 'Asia', 'Asia/Ho_Chi_Minh', 223),
(224, 'Asia', 'Asia/Hong_Kong', 224),
(225, 'Asia', 'Asia/Irkutsk', 225),
(226, 'Asia', 'Asia/Jakarta', 226),
(227, 'Asia', 'Asia/Jayapura', 227),
(228, 'Asia', 'Asia/Jerusalem', 228),
(229, 'Asia', 'Asia/Kabul', 229),
(230, 'Asia', 'Asia/Kamchatka', 230),
(231, 'Asia', 'Asia/Karachi', 231),
(232, 'Asia', 'Asia/Kathmandu', 232),
(233, 'Asia', 'Asia/Khandyga', 233),
(234, 'Asia', 'Asia/Kolkata', 234),
(235, 'Asia', 'Asia/Krasnoyarsk', 235),
(236, 'Asia', 'Asia/Kuala_Lumpur', 236),
(237, 'Asia', 'Asia/Kuching', 237),
(238, 'Asia', 'Asia/Kuwait', 238),
(239, 'Asia', 'Asia/Macau', 239),
(240, 'Asia', 'Asia/Magadan', 240),
(241, 'Asia', 'Asia/Makassar', 241),
(242, 'Asia', 'Asia/Manila', 242),
(243, 'Asia', 'Asia/Muscat', 243),
(244, 'Asia', 'Asia/Nicosia', 244),
(245, 'Asia', 'Asia/Novokuznetsk', 245),
(246, 'Asia', 'Asia/Novosibirsk', 246),
(247, 'Asia', 'Asia/Omsk', 247),
(248, 'Asia', 'Asia/Oral', 248),
(249, 'Asia', 'Asia/Phnom_Penh', 249),
(250, 'Asia', 'Asia/Pontianak', 250),
(251, 'Asia', 'Asia/Pyongyang', 251),
(252, 'Asia', 'Asia/Qatar', 252),
(253, 'Asia', 'Asia/Qyzylorda', 253),
(254, 'Asia', 'Asia/Riyadh', 254),
(255, 'Asia', 'Asia/Sakhalin', 255),
(256, 'Asia', 'Asia/Samarkand', 256),
(257, 'Asia', 'Asia/Seoul', 257),
(258, 'Asia', 'Asia/Shanghai', 258),
(259, 'Asia', 'Asia/Singapore', 259),
(260, 'Asia', 'Asia/Srednekolymsk', 260),
(261, 'Asia', 'Asia/Taipei', 261),
(262, 'Asia', 'Asia/Tashkent', 262),
(263, 'Asia', 'Asia/Tbilisi', 263),
(264, 'Asia', 'Asia/Tehran', 264),
(265, 'Asia', 'Asia/Thimphu', 265),
(266, 'Asia', 'Asia/Tokyo', 266),
(267, 'Asia', 'Asia/Tomsk', 267),
(268, 'Asia', 'Asia/Ulaanbaatar', 268),
(269, 'Asia', 'Asia/Urumqi', 269),
(270, 'Asia', 'Asia/Ust-Nera', 270),
(271, 'Asia', 'Asia/Vientiane', 271),
(272, 'Asia', 'Asia/Vladivostok', 272),
(273, 'Asia', 'Asia/Yakutsk', 273),
(274, 'Asia', 'Asia/Yangon', 274),
(275, 'Asia', 'Asia/Yekaterinburg', 275),
(276, 'Asia', 'Asia/Yerevan', 276),
(646, 'America', 'America/Adak', 277),
(647, 'America', 'America/Anchorage', 278),
(648, 'America', 'America/Anguilla', 279),
(649, 'America', 'America/Antigua', 280),
(650, 'America', 'America/Araguaina', 281),
(651, 'America', 'America/Argentina/Buenos_Aires', 282),
(652, 'America', 'America/Argentina/Catamarca', 283),
(653, 'America', 'America/Argentina/Cordoba', 284),
(654, 'America', 'America/Argentina/Jujuy', 285),
(655, 'America', 'America/Argentina/La_Rioja', 286),
(656, 'America', 'America/Argentina/Mendoza', 287),
(657, 'America', 'America/Argentina/Rio_Gallegos', 288),
(658, 'America', 'America/Argentina/Salta', 289),
(659, 'America', 'America/Argentina/San_Juan', 290),
(660, 'America', 'America/Argentina/San_Luis', 291),
(661, 'America', 'America/Argentina/Tucuman', 292),
(662, 'America', 'America/Argentina/Ushuaia', 293),
(663, 'America', 'America/Aruba', 294),
(664, 'America', 'America/Asuncion', 295),
(665, 'America', 'America/Atikokan', 296),
(666, 'America', 'America/Bahia', 297),
(667, 'America', 'America/Bahia_Banderas', 298),
(668, 'America', 'America/Barbados', 299),
(669, 'America', 'America/Belem', 300),
(670, 'America', 'America/Belize', 301),
(671, 'America', 'America/Blanc-Sablon', 302),
(672, 'America', 'America/Boa_Vista', 303),
(673, 'America', 'America/Bogota', 304),
(674, 'America', 'America/Boise', 305),
(675, 'America', 'America/Cambridge_Bay', 306),
(676, 'America', 'America/Campo_Grande', 307),
(677, 'America', 'America/Cancun', 308),
(678, 'America', 'America/Caracas', 309),
(679, 'America', 'America/Cayenne', 310),
(680, 'America', 'America/Cayman', 311),
(681, 'America', 'America/Chicago', 312),
(682, 'America', 'America/Chihuahua', 313),
(683, 'America', 'America/Costa_Rica', 314),
(684, 'America', 'America/Creston', 315),
(685, 'America', 'America/Cuiaba', 316),
(686, 'America', 'America/Curacao', 317),
(687, 'America', 'America/Danmarkshavn', 318),
(688, 'America', 'America/Dawson', 319),
(689, 'America', 'America/Dawson_Creek', 320),
(690, 'America', 'America/Denver', 321),
(691, 'America', 'America/Detroit', 322),
(692, 'America', 'America/Dominica', 323),
(693, 'America', 'America/Edmonton', 324),
(694, 'America', 'America/Eirunepe', 325),
(695, 'America', 'America/El_Salvador', 326),
(696, 'America', 'America/Fort_Nelson', 327),
(697, 'America', 'America/Fortaleza', 328),
(698, 'America', 'America/Glace_Bay', 329),
(699, 'America', 'America/Godthab', 330),
(700, 'America', 'America/Goose_Bay', 331),
(701, 'America', 'America/Grand_Turk', 332),
(702, 'America', 'America/Grenada', 333),
(703, 'America', 'America/Guadeloupe', 334),
(704, 'America', 'America/Guatemala', 335),
(705, 'America', 'America/Guayaquil', 336),
(706, 'America', 'America/Guyana', 337),
(707, 'America', 'America/Halifax', 338),
(708, 'America', 'America/Havana', 339),
(709, 'America', 'America/Hermosillo', 340),
(710, 'America', 'America/Indiana/Indianapolis', 341),
(711, 'America', 'America/Indiana/Knox', 342),
(712, 'America', 'America/Indiana/Marengo', 343),
(713, 'America', 'America/Indiana/Petersburg', 344),
(714, 'America', 'America/Indiana/Tell_City', 345),
(715, 'America', 'America/Indiana/Vevay', 346),
(716, 'America', 'America/Indiana/Vincennes', 347),
(717, 'America', 'America/Indiana/Winamac', 348),
(718, 'America', 'America/Inuvik', 349),
(719, 'America', 'America/Iqaluit', 350),
(720, 'America', 'America/Jamaica', 351),
(721, 'America', 'America/Juneau', 352),
(722, 'America', 'America/Kentucky/Louisville', 353),
(723, 'America', 'America/Kentucky/Monticello', 354),
(724, 'America', 'America/Kralendijk', 355),
(725, 'America', 'America/La_Paz', 356),
(726, 'America', 'America/Lima', 357),
(727, 'America', 'America/Los_Angeles', 358),
(728, 'America', 'America/Lower_Princes', 359),
(729, 'America', 'America/Maceio', 360),
(730, 'America', 'America/Managua', 361),
(731, 'America', 'America/Manaus', 362),
(732, 'America', 'America/Marigot', 363),
(733, 'America', 'America/Martinique', 364),
(734, 'America', 'America/Matamoros', 365),
(735, 'America', 'America/Mazatlan', 366),
(736, 'America', 'America/Menominee', 367),
(737, 'America', 'America/Merida', 368),
(738, 'America', 'America/Metlakatla', 369),
(739, 'America', 'America/Mexico_City', 370),
(740, 'America', 'America/Miquelon', 371),
(741, 'America', 'America/Moncton', 372),
(742, 'America', 'America/Monterrey', 373),
(743, 'America', 'America/Montevideo', 374),
(744, 'America', 'America/Montserrat', 375),
(745, 'America', 'America/Nassau', 376),
(746, 'America', 'America/New_York', 377),
(747, 'America', 'America/Nipigon', 378),
(748, 'America', 'America/Nome', 379),
(749, 'America', 'America/Noronha', 380),
(750, 'America', 'America/North_Dakota/Beulah', 381),
(751, 'America', 'America/North_Dakota/Center', 382),
(752, 'America', 'America/North_Dakota/New_Salem', 383),
(753, 'America', 'America/Ojinaga', 384),
(754, 'America', 'America/Panama', 385),
(755, 'America', 'America/Pangnirtung', 386),
(756, 'America', 'America/Paramaribo', 387),
(757, 'America', 'America/Phoenix', 388),
(758, 'America', 'America/Port-au-Prince', 389),
(759, 'America', 'America/Port_of_Spain', 390),
(760, 'America', 'America/Porto_Velho', 391),
(761, 'America', 'America/Puerto_Rico', 392),
(762, 'America', 'America/Punta_Arenas', 393),
(763, 'America', 'America/Rainy_River', 394),
(764, 'America', 'America/Rankin_Inlet', 395),
(765, 'America', 'America/Recife', 396),
(766, 'America', 'America/Regina', 397),
(767, 'America', 'America/Resolute', 398),
(768, 'America', 'America/Rio_Branco', 399),
(769, 'America', 'America/Santarem', 400),
(770, 'America', 'America/Santiago', 401),
(771, 'America', 'America/Santo_Domingo', 402),
(772, 'America', 'America/Sao_Paulo', 403),
(773, 'America', 'America/Scoresbysund', 404),
(774, 'America', 'America/Sitka', 405),
(775, 'America', 'America/St_Barthelemy', 406),
(776, 'America', 'America/St_Johns', 407),
(777, 'America', 'America/St_Kitts', 408),
(778, 'America', 'America/St_Lucia', 409),
(779, 'America', 'America/St_Thomas', 410),
(780, 'America', 'America/St_Vincent', 411),
(781, 'America', 'America/Swift_Current', 412),
(782, 'America', 'America/Tegucigalpa', 413),
(783, 'America', 'America/Thule', 414),
(784, 'America', 'America/Thunder_Bay', 415),
(785, 'America', 'America/Tijuana', 416),
(786, 'America', 'America/Toronto', 417),
(787, 'America', 'America/Tortola', 418),
(788, 'America', 'America/Vancouver', 419),
(789, 'America', 'America/Whitehorse', 420),
(790, 'America', 'America/Winnipeg', 421),
(791, 'America', 'America/Yakutat', 422),
(792, 'America', 'America/Yellowknife', 423);

-- --------------------------------------------------------

--
-- Table structure for table `tbl_users`
--

CREATE TABLE `tbl_users` (
  `id` int(10) NOT NULL,
  `first_name` varchar(70) NOT NULL DEFAULT 'Grace',
  `last_name` varchar(70) NOT NULL DEFAULT 'Kway',
  `gender` varchar(6) NOT NULL DEFAULT 'Female',
  `phone` varchar(70) NOT NULL DEFAULT '+255765435392',
  `city` varchar(70) NOT NULL DEFAULT '-',
  `street` varchar(70) NOT NULL DEFAULT '-',
  `email` varchar(70) NOT NULL DEFAULT 'gracekway76@gmail.com',
  `login` varchar(255) NOT NULL DEFAULT '$2y$10$8mhOTnS7vo9xou44cbm05.ylOSrV5B2XnAWIjp6WO2991qpSNU2ne',
  `level` int(2) NOT NULL DEFAULT 2 COMMENT '0 = Admin, 1 = Staff, 2 = User',
  `status` int(2) NOT NULL DEFAULT 1 COMMENT '1 = Active, 0 = Inactive'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tbl_users`
--

INSERT INTO `tbl_users` (`id`, `first_name`, `last_name`, `gender`, `phone`, `city`, `street`, `email`, `login`, `level`, `status`) VALUES
(1567, 'Bwire', 'Mashauri', 'Male', '+255765435392', 'Dar es Salaam', 'Pugu Kona', 'bwiremashauri5@gmail.com', '$2y$10$p0GpDhTDjjU3mZWsZbznGuTYIbPrlvQscdha9IsoClk3wnUVWRLOC', 0, 1);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `tbl_countries`
--
ALTER TABLE `tbl_countries`
  ADD PRIMARY KEY (`countrycode`);

--
-- Indexes for table `tbl_insuarance_category`
--
ALTER TABLE `tbl_insuarance_category`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tbl_insuarance_policy`
--
ALTER TABLE `tbl_insuarance_policy`
  ADD PRIMARY KEY (`id`),
  ADD KEY `category` (`category`),
  ADD KEY `sub_category` (`sub_category`);

--
-- Indexes for table `tbl_insuarance_sub_category`
--
ALTER TABLE `tbl_insuarance_sub_category`
  ADD PRIMARY KEY (`id`),
  ADD KEY `category` (`category`);

--
-- Indexes for table `tbl_login_sessions`
--
ALTER TABLE `tbl_login_sessions`
  ADD PRIMARY KEY (`sess_id`),
  ADD KEY `account` (`account`);

--
-- Indexes for table `tbl_notifications`
--
ALTER TABLE `tbl_notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user` (`user`),
  ADD KEY `ticket` (`ticket`);

--
-- Indexes for table `tbl_organization`
--
ALTER TABLE `tbl_organization`
  ADD PRIMARY KEY (`name`);

--
-- Indexes for table `tbl_policy_applications`
--
ALTER TABLE `tbl_policy_applications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `member_id` (`member_id`),
  ADD KEY `policy_id` (`policy_id`),
  ADD KEY `approved_by` (`approved_by`);

--
-- Indexes for table `tbl_smtp`
--
ALTER TABLE `tbl_smtp`
  ADD PRIMARY KEY (`server`);

--
-- Indexes for table `tbl_tickets`
--
ALTER TABLE `tbl_tickets`
  ADD PRIMARY KEY (`id`),
  ADD KEY `member_id` (`member_id`),
  ADD KEY `category` (`category`),
  ADD KEY `assigned_to` (`assigned_to`);

--
-- Indexes for table `tbl_tickets_replies`
--
ALTER TABLE `tbl_tickets_replies`
  ADD PRIMARY KEY (`id`),
  ADD KEY `ticket` (`ticket`),
  ADD KEY `sender` (`sender`);

--
-- Indexes for table `tbl_ticket_categories`
--
ALTER TABLE `tbl_ticket_categories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tbl_timezones`
--
ALTER TABLE `tbl_timezones`
  ADD PRIMARY KEY (`pid`);

--
-- Indexes for table `tbl_users`
--
ALTER TABLE `tbl_users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `tbl_insuarance_category`
--
ALTER TABLE `tbl_insuarance_category`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `tbl_insuarance_policy`
--
ALTER TABLE `tbl_insuarance_policy`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `tbl_insuarance_sub_category`
--
ALTER TABLE `tbl_insuarance_sub_category`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `tbl_notifications`
--
ALTER TABLE `tbl_notifications`
  MODIFY `id` int(70) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `tbl_tickets`
--
ALTER TABLE `tbl_tickets`
  MODIFY `id` int(70) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `tbl_tickets_replies`
--
ALTER TABLE `tbl_tickets_replies`
  MODIFY `id` int(70) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `tbl_ticket_categories`
--
ALTER TABLE `tbl_ticket_categories`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `tbl_timezones`
--
ALTER TABLE `tbl_timezones`
  MODIFY `pid` int(255) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=424;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tbl_insuarance_policy`
--
ALTER TABLE `tbl_insuarance_policy`
  ADD CONSTRAINT `tbl_insuarance_policy_ibfk_1` FOREIGN KEY (`category`) REFERENCES `tbl_insuarance_category` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_insuarance_policy_ibfk_2` FOREIGN KEY (`sub_category`) REFERENCES `tbl_insuarance_sub_category` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_insuarance_sub_category`
--
ALTER TABLE `tbl_insuarance_sub_category`
  ADD CONSTRAINT `tbl_insuarance_sub_category_ibfk_1` FOREIGN KEY (`category`) REFERENCES `tbl_insuarance_category` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_login_sessions`
--
ALTER TABLE `tbl_login_sessions`
  ADD CONSTRAINT `tbl_login_sessions_ibfk_1` FOREIGN KEY (`account`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_notifications`
--
ALTER TABLE `tbl_notifications`
  ADD CONSTRAINT `tbl_notifications_ibfk_1` FOREIGN KEY (`user`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_notifications_ibfk_2` FOREIGN KEY (`ticket`) REFERENCES `tbl_tickets` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_policy_applications`
--
ALTER TABLE `tbl_policy_applications`
  ADD CONSTRAINT `tbl_policy_applications_ibfk_1` FOREIGN KEY (`policy_id`) REFERENCES `tbl_insuarance_policy` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_policy_applications_ibfk_2` FOREIGN KEY (`member_id`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_policy_applications_ibfk_3` FOREIGN KEY (`approved_by`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_tickets`
--
ALTER TABLE `tbl_tickets`
  ADD CONSTRAINT `tbl_tickets_ibfk_1` FOREIGN KEY (`category`) REFERENCES `tbl_ticket_categories` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_tickets_ibfk_2` FOREIGN KEY (`member_id`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_tickets_ibfk_3` FOREIGN KEY (`assigned_to`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `tbl_tickets_replies`
--
ALTER TABLE `tbl_tickets_replies`
  ADD CONSTRAINT `tbl_tickets_replies_ibfk_1` FOREIGN KEY (`ticket`) REFERENCES `tbl_tickets` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `tbl_tickets_replies_ibfk_2` FOREIGN KEY (`sender`) REFERENCES `tbl_users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
