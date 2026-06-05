from enum import Enum
import functools
import re
from requests.adapters import HTTPAdapter
import requests
import time
import hashlib
from typing import List, Text

HTTP_MAX_RETRIES = 5


class FilterUrl:
    def __init__(self, filter_url: Text):
        self.filter_url = filter_url

    def url(self) -> Text:
        return self.filter_url

    def hash(self) -> Text:
        return hashlib.sha256(self.filter_url.encode()).hexdigest()


class FilterException(Exception):
    pass


class FilterFetchException(FilterException, requests.exceptions.RequestException):
    pass


class FilterFetchStatusNotOkException(FilterException):
    pass


class FilterGroup(Enum):
    DEFAULT = "default"
    REGIONAL = "regional"
    ADS = "ads"
    PRIVACY = "privacy"
    MALWARE = "malware"
    SOCIAL = "social"


class Filter:
    def __init__(
        self,
        filter_group: FilterGroup,
        url: FilterUrl,
        title: Text,
        enabled_by_default=False,
    ) -> None:
        self.filter_group = filter_group
        self.url = url
        self.title = title
        self.enabled_by_default = enabled_by_default

    def to_dict(self) -> Text:
        return {
            "file_name": f"{self.url.hash()}.txt",
            "source_url": self.url.url(),
            "title": self.title,
            "group": str(self.filter_group.value),
            "enabled_by_default": self.enabled_by_default,
        }

    def _download(self) -> Text:
        session = requests.Session()

        session.mount("http://", HTTPAdapter(max_retries=HTTP_MAX_RETRIES))
        session.mount("https://", HTTPAdapter(max_retries=HTTP_MAX_RETRIES))

        try:
            response = session.get(f"{self.url.url()}?t={int(time.time())}")
        except requests.exceptions.RequestException as e:
            raise FilterFetchException(e)

        if not response.ok:
            raise FilterFetchStatusNotOkException

        return response.text

    def save_to_registry(self) -> None:
        filter = self._download()

        try:
            with open(f"registry/{self.url.hash()}.txt", "r") as f:
                current_filter = f.read()
        except FileNotFoundError:
            current_filter = ""

        # We strip comments before comparing as some lists
        # are just adding the current timestamp in filter header's comments.
        if _strip_comments_from_filter_list(filter) == _strip_comments_from_filter_list(
            current_filter
        ):
            return

        with open(f"registry/{self.url.hash()}.txt", "w") as f:
            f.write(filter)


def _strip_comments_from_filter_list(filter_list: Text) -> Text:
    filter_list_new = filter_list.splitlines()

    try:
        if filter_list_new[0].startswith("[") and filter_list_new[0].endswith("]"):
            del filter_list_new[0]

    except IndexError:
        return ""

    filter_list_new = [
        filter
        for filter in filter_list_new
        if not filter.startswith("!") and not filter == ""
    ]

    filter_list_new.sort()

    return "\n".join(filter_list_new)


ADBLOCK_PLUS_TITLE_PREFIX = "[Ad-PLUS]"
REGIONAL_CODE_PREFIX_PATTERN = re.compile(
    r"^([A-Za-z]{2,8}(?:,\s*[A-Za-z]{2,8})*):\s*(.+)$"
)

ADBLOCK_PLUS_SUBSCRIPTIONS = [
    (FilterGroup.ADS, "EasyList", "https://easylist-downloads.adblockplus.org/easylist.txt"),
    (
        FilterGroup.REGIONAL,
        "ABPindo+EasyList",
        "https://easylist-downloads.adblockplus.org/abpindo+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "ABPindo",
        "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "ABPVN List+EasyList",
        "https://easylist-downloads.adblockplus.org/abpvn+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "ABPVN List",
        "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Bulgarian list+EasyList",
        "https://easylist-downloads.adblockplus.org/bulgarian_list+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Bulgarian list",
        "https://stanev.org/abp/adblock_bg.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Dandelion Sprout's Nordic Filters+EasyList",
        "https://easylist-downloads.adblockplus.org/dandelion_sprouts_nordic_filters+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Dandelion Sprout's Nordic Filters",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList alternate versions/NordicFiltersABP-Inclusion.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList China+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList China",
        "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    ),
    (
        FilterGroup.SOCIAL,
        "CJX's Annoyance List",
        "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Czech and Slovak+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistczechslovak+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Czech and Slovak",
        "https://raw.github.com/tomasko126/easylistczechandslovak/master/filters.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Dutch+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistdutch+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Dutch",
        "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Germany+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistgermany+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Germany",
        "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Hebrew+EasyList",
        "https://easylist-downloads.adblockplus.org/israellist+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Hebrew",
        "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Italy+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistitaly+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Italy",
        "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Lithuania+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistlithuania+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Lithuania",
        "https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Polish+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistpolish+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Polish",
        "https://easylist-downloads.adblockplus.org/easylistpolish.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Portuguese+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistportuguese+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Portuguese",
        "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Spanish+EasyList",
        "https://easylist-downloads.adblockplus.org/easylistspanish+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "EasyList Spanish",
        "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Global Filters+EasyList",
        "https://easylist-downloads.adblockplus.org/global-filters+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Global Filters",
        "https://easylist-downloads.adblockplus.org/global-filters.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "hufilter+EasyList",
        "https://easylist-downloads.adblockplus.org/hufilter+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "hufilter",
        "https://cdn.jsdelivr.net/gh/hufilter/hufilter@gh-pages/hufilter.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "IndianList+EasyList",
        "https://easylist-downloads.adblockplus.org/indianlist+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "IndianList",
        "https://easylist-downloads.adblockplus.org/indianlist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Japanese Filters+EasyList",
        "https://easylist-downloads.adblockplus.org/japanese-filters+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Japanese Filters",
        "https://easylist-downloads.adblockplus.org/japanese-filters.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "KoreanList+EasyList",
        "https://easylist-downloads.adblockplus.org/koreanlist+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "KoreanList",
        "https://easylist-downloads.adblockplus.org/koreanlist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Latvian List+EasyList",
        "https://easylist-downloads.adblockplus.org/latvianlist+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Latvian List",
        "https://raw.githubusercontent.com/Latvian-List/adblock-latvian/master/lists/latvian-list.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Liste FR+EasyList",
        "https://easylist-downloads.adblockplus.org/liste_fr+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Liste FR",
        "https://easylist-downloads.adblockplus.org/liste_fr.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Liste AR+Liste FR+EasyList",
        "https://easylist-downloads.adblockplus.org/liste_ar+liste_fr+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Liste AR",
        "https://easylist-downloads.adblockplus.org/Liste_AR.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "ROList+EasyList",
        "https://easylist-downloads.adblockplus.org/rolist+easylist.txt",
    ),
    (FilterGroup.REGIONAL, "ROList", "https://www.zoso.ro/pages/rolist.txt"),
    (
        FilterGroup.REGIONAL,
        "RuAdList+EasyList",
        "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Turkish Filters+EasyList",
        "https://easylist-downloads.adblockplus.org/turkish-filters+easylist.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Turkish Filters",
        "https://easylist-downloads.adblockplus.org/turkish-filters.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Colombian filters by yecarrillo",
        "https://raw.githubusercontent.com/yecarrillo/adblock-colombia/master/adblock_co.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Icelandic ABP List",
        "https://adblock.gardar.net/is.abp.txt",
    ),
    (FilterGroup.REGIONAL, "void.gr", "https://www.void.gr/kargig/void-gr-filters.txt"),
    (
        FilterGroup.REGIONAL,
        "280blocker for japanese mobile site",
        "https://280blocker.net/files/280blocker_adblock.txt",
    ),
    (FilterGroup.REGIONAL, "ABP Japanese Filters", "https://bit.ly/11QrCfx"),
    (
        FilterGroup.REGIONAL,
        "AdBlockFarsi",
        "https://raw.githubusercontent.com/SlashArash/adblockfa/master/adblockfa.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Eesti saitidele kohandatud filter",
        "https://adblock.ee/list.php",
    ),
    (FilterGroup.REGIONAL, "Estonian filters by Gurud.ee", "https://gurud.ee/ab.txt"),
    (
        FilterGroup.ADS,
        "Peter Lowe's list",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&mimetype=plaintext",
    ),
    (
        FilterGroup.REGIONAL,
        "Raajje Adlist",
        "https://raw.githubusercontent.com/evenxzero/Raajje-AdList/master/filter.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Tiswagos Liri AdBlockList",
        "https://raw.githubusercontent.com/Xaival/AdBlockList/main/Adblock_list.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "Xfiles",
        "https://raw.githubusercontent.com/gioxx/xfiles/master/filtri.txt",
    ),
    (
        FilterGroup.REGIONAL,
        "YousList",
        "https://raw.githubusercontent.com/yous/YousList/master/youslist.txt",
    ),
    (
        FilterGroup.ADS,
        "ABP filters",
        "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",
    ),
    (
        FilterGroup.MALWARE,
        "Spam404",
        "https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt",
    ),
    (
        FilterGroup.SOCIAL,
        "Fanboy's Notifications Blocking List",
        "https://easylist-downloads.adblockplus.org/fanboy-notifications.txt",
    ),
    (
        FilterGroup.PRIVACY,
        "CPBL Filters for Adblock Plus (Mini)",
        "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/MiniLists/cpbl-abp-mini.txt",
    ),
    (
        FilterGroup.MALWARE,
        "NoCoin",
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    ),
    (
        FilterGroup.PRIVACY,
        "Stevo's GenAI Blocklist",
        "https://raw.githubusercontent.com/Stevoisiak/Stevos-GenAI-Blocklist/refs/heads/main/GenAI-Blocklist.txt",
    ),
    (
        FilterGroup.PRIVACY,
        "EasyPrivacy",
        "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    ),
    (
        FilterGroup.PRIVACY,
        "EasyPrivacy+EasyList",
        "https://easylist-downloads.adblockplus.org/easyprivacy+easylist.txt",
    ),
    (
        FilterGroup.SOCIAL,
        "Fanboy's Social Blocking List",
        "https://easylist-downloads.adblockplus.org/fanboy-social.txt",
    ),
]


def _normalize_adblock_plus_title(title: Text) -> Text:
    title = title.replace(ADBLOCK_PLUS_TITLE_PREFIX, "")

    if ":" in title:
        title = title.split(":", 1)[1]

    for token in ["blocking", "filters", "filter", "list"]:
        title = title.replace(token, "")
        title = title.replace(token.title(), "")

    return " ".join(
        title.lower()
        .replace("’", "'")
        .replace("'", "")
        .replace("nordiske filtre", "nordic")
        .split()
    )


ADBLOCK_PLUS_REGIONAL_CODES = {
    _normalize_adblock_plus_title(title): codes
    for title, codes in [
        ("ABPindo+EasyList", "IDN, MYS"),
        ("ABPindo", "IDN, MYS"),
        ("ABPVN List+EasyList", "VNM"),
        ("ABPVN List", "VNM"),
        ("Bulgarian list+EasyList", "BGR"),
        ("Bulgarian list", "BGR"),
        ("Dandelion Sprout's Nordic Filters+EasyList", "NOR, DNK, ISL, FRO, GRL, FIN"),
        ("Dandelion Sprout's Nordic Filters", "NOR, DNK, ISL, FRO, GRL, FIN"),
        ("Dandelion Sprouts nordiske filtre", "NOR, DNK, ISL, FRO, GRL, FIN"),
        ("EasyList China+EasyList", "CHN"),
        ("EasyList China", "CHN"),
        ("EasyList Czech and Slovak+EasyList", "CZE, SVK"),
        ("EasyList Czech and Slovak", "CZE, SVK"),
        ("EasyList Dutch+EasyList", "NLD"),
        ("EasyList Dutch", "NLD"),
        ("EasyList Germany+EasyList", "DEU"),
        ("EasyList Germany", "DEU"),
        ("EasyList Hebrew+EasyList", "ISR"),
        ("EasyList Hebrew", "ISR"),
        ("EasyList Italy+EasyList", "ITA"),
        ("EasyList Italy", "ITA"),
        ("EasyList Lithuania+EasyList", "LTU"),
        ("EasyList Lithuania", "LTU"),
        ("EasyList Polish+EasyList", "POL"),
        ("EasyList Polish", "POL"),
        ("EasyList Portuguese+EasyList", "PRT, BRA"),
        ("EasyList Portuguese", "PRT, BRA"),
        ("EasyList Spanish+EasyList", "ESP"),
        ("EasyList Spanish", "ESP"),
        ("Global Filters+EasyList", "THA, GRC, SVN, HRV, SRB, BIH, PHL"),
        ("Global Filters", "THA, GRC, SVN, HRV, SRB, BIH, PHL"),
        ("hufilter+EasyList", "HUN"),
        ("hufilter", "HUN"),
        ("IndianList+EasyList", "IND"),
        ("IndianList", "IND"),
        ("Japanese Filters+EasyList", "JPN"),
        ("Japanese Filters", "JPN"),
        ("KoreanList+EasyList", "KOR"),
        ("KoreanList", "KOR"),
        ("Latvian List+EasyList", "LVA"),
        ("Latvian List", "LVA"),
        ("Liste FR+EasyList", "FRA"),
        ("Liste FR", "FRA"),
        ("Liste AR+Liste FR+EasyList", "ARA"),
        ("Liste AR", "ARA"),
        ("ROList+EasyList", "ROU"),
        ("ROList", "ROU"),
        ("RuAdList+EasyList", "RUS"),
        ("Turkish Filters+EasyList", "TUR"),
        ("Turkish Filters", "TUR"),
        ("Colombian filters by yecarrillo", "COL"),
        ("Icelandic ABP List", "ISL"),
        ("void.gr", "GRC"),
        ("280blocker for japanese mobile site", "JPN"),
        ("ABP Japanese Filters", "JPN"),
        ("AdBlockFarsi", "IRN"),
        ("Eesti saitidele kohandatud filter", "EST"),
        ("Estonian filters by Gurud.ee", "EST"),
        ("Raajje Adlist", "MDV"),
        ("Tiswagos Liri AdBlockList", "ESP"),
        ("Xfiles", "ITA"),
        ("YousList", "KOR"),
    ]
}


def _prefix_adblock_plus_title(title: Text) -> Text:
    if title.startswith(ADBLOCK_PLUS_TITLE_PREFIX):
        return title

    return f"{ADBLOCK_PLUS_TITLE_PREFIX} {title}"


def _is_combined_easylist_subscription(title: Text) -> bool:
    return "+EasyList" in title


def _format_adblock_plus_title(filter_group: FilterGroup, title: Text) -> Text:
    title = _prefix_adblock_plus_title(title)

    if filter_group != FilterGroup.REGIONAL:
        return title

    display_title = title.replace(ADBLOCK_PLUS_TITLE_PREFIX, "", 1).strip()
    existing_code_match = REGIONAL_CODE_PREFIX_PATTERN.match(display_title)

    base_title = (
        existing_code_match.group(2).strip()
        if existing_code_match
        else display_title
    )
    codes = ADBLOCK_PLUS_REGIONAL_CODES.get(_normalize_adblock_plus_title(base_title))

    if not codes:
        if existing_code_match and existing_code_match.group(1).isupper():
            return title

        return title

    return f"{ADBLOCK_PLUS_TITLE_PREFIX} {codes}: {base_title}"


def _merge_adblock_plus_subscriptions(filters: List[Filter]) -> None:
    adblock_plus_urls = {url for _, _, url in ADBLOCK_PLUS_SUBSCRIPTIONS}
    adblock_plus_titles = {
        _normalize_adblock_plus_title(title)
        for _, title, _ in ADBLOCK_PLUS_SUBSCRIPTIONS
    }

    existing_urls = set()
    existing_titles = set()

    for filter in filters:
        existing_urls.add(filter.url.url())

        normalized_title = _normalize_adblock_plus_title(filter.title)
        existing_titles.add(normalized_title)

        if filter.url.url() in adblock_plus_urls or normalized_title in adblock_plus_titles:
            filter.title = _format_adblock_plus_title(filter.filter_group, filter.title)

    for filter_group, title, url in ADBLOCK_PLUS_SUBSCRIPTIONS:
        normalized_title = _normalize_adblock_plus_title(title)

        if (
            url in existing_urls
            or normalized_title in existing_titles
            or _is_combined_easylist_subscription(title)
        ):
            continue

        filters.append(
            Filter(
                filter_group=filter_group,
                url=FilterUrl(url),
                title=_format_adblock_plus_title(filter_group, title),
                enabled_by_default=filter_group == FilterGroup.MALWARE,
            )
        )
        existing_urls.add(url)
        existing_titles.add(normalized_title)


@functools.lru_cache()
def get_filters() -> List[Filter]:
    """
    A filter set mostly derived from https://github.com/gorhill/uBlock/blob/master/assets/assets.json
    """
    filters = [
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"
            ),
            title="uBlock filters",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt"
            ),
            title="uBlock filters - Badware risks",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt"
            ),
            title="uBlock filters - Privacy",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt"
            ),
            title="uBlock filters - Resource abuse",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt"
            ),
            title="uBlock filters - Unbreak",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.DEFAULT,
            url=FilterUrl(
                "https://ublockorigin.github.io/uAssetsCDN/filters/quick-fixes.min.txt"
            ),
            title="uBlock filters - Quick fixes",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.ADS,
            url=FilterUrl(
                "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt"
            ),
            title="AdGuard Base",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.ADS,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/11.txt"),
            title="AdGuard Mobile Ads",
        ),
        Filter(
            filter_group=FilterGroup.ADS,
            url=FilterUrl("https://easylist.to/easylist/easylist.txt"),
            title="EasyList",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.PRIVACY,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/3.txt"),
            title="AdGuard Tracking Protection",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.PRIVACY,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/17.txt"),
            title="AdGuard URL Tracking Protection",
        ),
        Filter(
            filter_group=FilterGroup.PRIVACY,
            url=FilterUrl("https://easylist-downloads.adblockplus.org/cntblock.txt"),
            title="RU AdList: Counters",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.PRIVACY,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/lan-block.txt"
            ),
            title="Block Outsider Intrusion into LAN",
        ),
        Filter(
            filter_group=FilterGroup.PRIVACY,
            url=FilterUrl("https://easylist.to/easylist/easyprivacy.txt"),
            title="EasyPrivacy",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.MALWARE,
            url=FilterUrl(
                "https://curben.gitlab.io/malware-filter/phishing-filter.txt"
            ),
            title="Phishing URL Blocklist",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.MALWARE,
            url=FilterUrl("https://curben.gitlab.io/malware-filter/pup-filter.txt"),
            title="PUP Domains Blocklist",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/14.txt"),
            title="AdGuard Annoyances",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/4.txt"),
            title="AdGuard Social Media",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://secure.fanboy.co.nz/fanboy-antifacebook.txt"),
            title="Anti-Facebook",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://secure.fanboy.co.nz/fanboy-annoyance.txt"),
            title="Fanboy's Annoyance",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://secure.fanboy.co.nz/fanboy-cookiemonster.txt"),
            title="EasyList Cookie",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl("https://easylist.to/easylist/fanboy-social.txt"),
            title="Fanboy's Social",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt"
            ),
            title="uBlock filters - Annoyances",
        ),
        Filter(
            filter_group=FilterGroup.SOCIAL,
            url=FilterUrl(
                "https://easylist-downloads.adblockplus.org/antiadblockfilters.txt"
            ),
            title="Adblock Warning Removal List",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.ADS,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/5.txt"),
            title="AdGuard Experimental filter",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://easylist-downloads.adblockplus.org/Liste_AR.txt"),
            title="ara: Liste AR",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://stanev.org/abp/adblock_bg.txt"),
            title="BGR: Bulgarian Adblock list",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://filters.adtidy.org/extension/ublock/filters/224.txt"
            ),
            title="CHN: AdGuard Chinese (中文)",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt"
            ),
            title="CZE, SVK: EasyList Czech and Slovak",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://easylist.to/easylistgermany/easylistgermany.txt"),
            title="DEU: EasyList Germany",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://adblock.ee/list.php"),
            title="EST: Eesti saitidele kohandatud filter",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/finnish-easylist-addition/finnish-easylist-addition/master/Finland_adb.txt"
            ),
            title="FIN: Adblock List for Finland",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/16.txt"),
            title="FRA: AdGuard Français",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://www.void.gr/kargig/void-gr-filters.txt"),
            title="GRC: Greek AdBlock Filter",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/hufilter/hufilter/master/hufilter-ublock.txt"
            ),
            title="HUN: hufilter",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt"
            ),
            title="IDN, MYS: ABPindo",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/farrokhi/adblock-iran/master/filter.txt"
            ),
            title="IRN: Adblock-Iran",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://adblock.gardar.net/is.abp.txt"),
            title="ISL: Icelandic ABP List",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt"
            ),
            title="ISR: EasyList Hebrew",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://easylist-downloads.adblockplus.org/easylistitaly.txt"
            ),
            title="ITA: EasyList Italy",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/gioxx/xfiles/master/filtri.txt"
            ),
            title="ITA: ABP X Files",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/7.txt"),
            title="JPN: AdGuard Japanese",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/yous/YousList/master/youslist.txt"
            ),
            title="KOR: YousList",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/EasyList-Lithuania/easylist_lithuania/master/easylistlithuania.txt"
            ),
            title="LTU: EasyList Lithuania",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://notabug.org/latvian-list/adblock-latvian/raw/master/lists/latvian-list.txt"
            ),
            title="LVA: Latvian List",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://easylist-downloads.adblockplus.org/easylistdutch.txt"
            ),
            title="NLD: EasyList Dutch",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianList.txt"
            ),
            title="NOR, DNK, ISL: Dandelion Sprouts nordiske filtre",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt"
            ),
            title="POL: Oficjalne Polskie Filtry do AdBlocka, uBlocka Origin i AdGuarda",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/anti-adblock.txt"
            ),
            title="POL: Oficjalne polskie filtry przeciwko alertom o Adblocku",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://road.adblock.ro/lista.txt"),
            title="ROU: Romanian Ad (ROad) Block List Light",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://filters.adtidy.org/extension/chromium/filters/1.txt"),
            title="RUS: AdGuard Russian",
            enabled_by_default=True,
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt"
            ),
            title="RuAdList+EasyList",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/hant0508/uBlock-filters/master/filters.txt"
            ),
            title="RUS: hant0508 additional filters",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://easylist-downloads.adblockplus.org/easylistspanish.txt"
            ),
            title="spa: EasyList Spanish",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/9.txt"),
            title="spa, por: AdGuard Spanish/Portuguese",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/betterwebleon/slovenian-list/master/filters.txt"
            ),
            title="SVN: Slovenian List",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt"
            ),
            title="SWE: Frellwit's Swedish Filter",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt"
            ),
            title="THA: EasyList Thailand",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl("https://filters.adtidy.org/extension/ublock/filters/13.txt"),
            title="TUR: AdGuard Turkish",
        ),
        Filter(
            filter_group=FilterGroup.REGIONAL,
            url=FilterUrl(
                "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn_ublock.txt"
            ),
            title="VIE: ABPVN List",
        ),
    ]

    _merge_adblock_plus_subscriptions(filters)

    return filters
