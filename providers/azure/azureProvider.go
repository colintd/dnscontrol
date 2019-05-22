package azure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/StackExchange/dnscontrol/providers/diff"
	"github.com/Azure/azure-sdk-for-go/services/dns/mgmt/2017-10-01/dns"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/pkg/errors"
)

// ZonesClient is an interface of dns.ZoneClient that can be stubbed for testing.
type ZonesClient interface {
	ListByResourceGroup(resourceGroupName string, top *int32) (result dns.ZoneListResult, err error)
	ListByResourceGroupNextResults(lastResults dns.ZoneListResult) (result dns.ZoneListResult, err error)
}

// RecordsClient is an interface of dns.RecordClient that can be stubbed for testing.
type RecordsClient interface {
	ListByDNSZone(resourceGroupName string, zoneName string, top *int32) (result dns.RecordSetListResult, err error)
	ListByDNSZoneNextResults(list dns.RecordSetListResult) (result dns.RecordSetListResult, err error)
	Delete(resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, ifMatch string) (result autorest.Response, err error)
	CreateOrUpdate(resourceGroupName string, zoneName string, relativeRecordSetName string, recordType dns.RecordType, parameters dns.RecordSet, ifMatch string, ifNoneMatch string) (result dns.RecordSet, err error)
}

type azureProvider struct {
	zonesClient   ZonesClient
	recordsClient RecordsClient
}

func newAzureReg(conf map[string]string) (providers.Registrar, error) {
	return newAzure(conf, nil)
}

func newAzureDsp(conf map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	return newAzure(conf, metadata)
}

func newAzure(m map[string]string, metadata json.RawMessage) (*azureProvider, error) {
	keyID, secretKey, tokenID := m["KeyId"], m["SecretKey"], m["Token"]

	// Azure uses a global endpoint and azuredomains
	// currently only has a single regional endpoint in us-east-1
	// http://docs.aws.amazon.com/general/latest/gr/rande.html#azure_region
	//config := &azure.Config{
	//	Region: azure.String("us-east-1"),
	//}

	// Token is optional and left empty unless required
	//if keyID != "" || secretKey != "" {
	//	config.Credentials = credentials.NewStaticCredentials(keyID, secretKey, tokenID)
	//}
	//sess := session.New(config)

	var dls *string = nil
	if val, ok := m["DelegationSet"]; ok {
		fmt.Printf("ROUTE53 DelegationSet %s configured\n", val)
		dls = sPtr(val)
	}
	api := &azureProvider{} //client: azure.New(sess), registrar: azured.New(sess)}
	err := api.getZones()
	if err != nil {
		return nil, err
	}
	return api, nil
}

var features = providers.DocumentationNotes{
	providers.CanUseAlias:            providers.Cannot(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Cannot("Azure doesn't allow deletion of default name servers"),
	providers.DocOfficiallySupported: providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSRV:              providers.Cannot(),
	providers.CanUseTXTMulti:         providers.Can(),
	providers.CanUseCAA:              providers.Cannot(),
	providers.CanUseRoute53Alias:         providers.Cannot(),
}

func init() {
	providers.RegisterDomainServiceProviderType("AZURE", newAzureDsp, features)
	providers.RegisterRegistrarType("AZURE", newAzureReg)
}

func sPtr(s string) *string {
	return &s
}

func withRetry(f func() error) {
	const maxRetries = 23
	// TODO: exponential backoff
	const sleepTime = 5 * time.Second
	var currentRetry int = 0
	for {
		err := f()
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "Rate exceeded") {
			currentRetry++
			if currentRetry >= maxRetries {
				return
			}
			fmt.Printf("============ Azure rate limit exceeded. Waiting %s to retry.\n", sleepTime)
			time.Sleep(sleepTime)
		} else {
			return
		}
	}
	return
}

func (r *azureProvider) getZones() error {
	var nextMarker *string
	r.zones = make(map[string]*azure.HostedZone)
	for {
		var out *azure.ListHostedZonesOutput
		var err error
		withRetry(func() error {
			inp := &azure.ListHostedZonesInput{Marker: nextMarker}
			out, err = r.client.ListHostedZones(inp)
			return err
		})
		if err != nil && strings.Contains(err.Error(), "is not authorized") {
			return errors.New("Check your credentials, your not authorized to perform actions on Route 53 AWS Service")
		} else if err != nil {
			return err
		}
		for _, z := range out.HostedZones {
			domain := strings.TrimSuffix(*z.Name, ".")
			r.zones[domain] = z
		}
		if out.NextMarker != nil {
			nextMarker = out.NextMarker
		} else {
			break
		}
	}
	return nil
}

type errNoExist struct {
	domain string
}

func (e errNoExist) Error() string {
	return fmt.Sprintf("Domain %s not found in your Azure account", e.domain)
}

func (r *azureProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {

	zone, ok := r.zones[domain]
	if !ok {
		return nil, errNoExist{domain}
	}
	var z *azure.GetHostedZoneOutput
	var err error
	withRetry(func() error {
		z, err = r.client.GetHostedZone(&azure.GetHostedZoneInput{Id: zone.Id})
		return err
	})
	if err != nil {
		return nil, err
	}
	ns := []*models.Nameserver{}
	if z.DelegationSet != nil {
		for _, nsPtr := range z.DelegationSet.NameServers {
			ns = append(ns, &models.Nameserver{Name: *nsPtr})
		}
	}
	return ns, nil
}

func (r *azureProvider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()

	var corrections = []*models.Correction{}
	zone, ok := r.zones[dc.Name]
	// add zone if it doesn't exist
	if !ok {
		return nil, errNoExist{dc.Name}
	}

	records, err := r.fetchRecordSets(zone.Id)
	if err != nil {
		return nil, err
	}

	var existingRecords = []*models.RecordConfig{}
	for _, set := range records {
		existingRecords = append(existingRecords, nativeToRecords(set, dc.Name)...)
	}

	// Normalize
	models.PostProcessRecords(existingRecords)

	// diff
	differ := diff.New(dc)
	namesToUpdate := differ.ChangedGroups(existingRecords)

	if len(namesToUpdate) == 0 {
		return nil, nil
	}

	updates := map[models.RecordKey][]*models.RecordConfig{}
	// for each name we need to update, collect relevant records from dc
	for k := range namesToUpdate {
		updates[k] = nil
		for _, rc := range dc.Records {
			if rc.Key() == k {
				updates[k] = append(updates[k], rc)
			}
		}
	}

	dels := []*azure.Change{}
	changes := []*azure.Change{}
	changeDesc := ""
	delDesc := ""
	for k, recs := range updates {
		chg := &azure.Change{}
		var rrset *azure.ResourceRecordSet
		if len(recs) == 0 {
			dels = append(dels, chg)
			chg.Action = sPtr("DELETE")
			delDesc += strings.Join(namesToUpdate[k], "\n") + "\n"
			// on delete just submit the original resource set we got from azure.
			for _, r := range records {
				if unescape(r.Name) == k.NameFQDN && (*r.Type == k.Type) {
					rrset = r
					break
				}
			}
			if rrset == nil {
				return nil, fmt.Errorf("No record set found to delete. Name: '%s'. Type: '%s'", k.NameFQDN, k.Type)
			}
		} else {
			changes = append(changes, chg)
			changeDesc += strings.Join(namesToUpdate[k], "\n") + "\n"
			// on change or create, just build a new record set from our desired state
			chg.Action = sPtr("UPSERT")
			rrset = &azure.ResourceRecordSet{
				Name: sPtr(k.NameFQDN),
				Type: sPtr(k.Type),
			}
			for _, r := range recs {
				val := r.GetTargetCombined()
				rr := &azure.ResourceRecord{
					Value: &val,
				}
				rrset.ResourceRecords = append(rrset.ResourceRecords, rr)
				i := int64(r.TTL)
				rrset.TTL = &i // TODO: make sure that ttls are consistent within a set
			}
		}
		chg.ResourceRecordSet = rrset
	}

	changeReq := &azure.ChangeResourceRecordSetsInput{
		ChangeBatch: &azure.ChangeBatch{Changes: changes},
	}

	delReq := &azure.ChangeResourceRecordSetsInput{
		ChangeBatch: &azure.ChangeBatch{Changes: dels},
	}

	addCorrection := func(msg string, req *azure.ChangeResourceRecordSetsInput) {
		corrections = append(corrections,
			&models.Correction{
				Msg: msg,
				F: func() error {
					var err error
					req.HostedZoneId = zone.Id
					withRetry(func() error {
						_, err = r.client.ChangeResourceRecordSets(req)
						return err
					})
					return err
				},
			})
	}

	if len(dels) > 0 {
		addCorrection(delDesc, delReq)
	}

	if len(changes) > 0 {
		addCorrection(changeDesc, changeReq)
	}

	return corrections, nil

}

func nativeToRecords(set *azure.ResourceRecordSet, origin string) []*models.RecordConfig {
	results := []*models.RecordConfig{}
	if set.AliasTarget != nil {
		rc := &models.RecordConfig{
			Type: "R53_ALIAS",
			TTL:  300,
			R53Alias: map[string]string{
				"type":    *set.Type,
				"zone_id": *set.AliasTarget.HostedZoneId,
			},
		}
		rc.SetLabelFromFQDN(unescape(set.Name), origin)
		rc.SetTarget(aws.StringValue(set.AliasTarget.DNSName))
		results = append(results, rc)
	} else if set.TrafficPolicyInstanceId != nil {
		// skip traffic policy records
	} else {
		for _, rec := range set.ResourceRecords {
			switch rtype := *set.Type; rtype {
			case "SOA":
				continue
			default:
				rc := &models.RecordConfig{TTL: uint32(*set.TTL)}
				rc.SetLabelFromFQDN(unescape(set.Name), origin)
				if err := rc.PopulateFromString(*set.Type, *rec.Value, origin); err != nil {
					panic(errors.Wrap(err, "unparsable record received from R53"))
				}
				results = append(results, rc)
			}
		}
	}
	return results
}

func getZoneID(zone *azure.HostedZone, r *models.RecordConfig) string {
	zoneID := r.R53Alias["zone_id"]
	if zoneID == "" {
		zoneID = aws.StringValue(zone.Id)
	}
	if strings.HasPrefix(zoneID, "/hostedzone/") {
		zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")
	}
	return zoneID
}

func (r *azureProvider) GetRegistrarCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	corrections := []*models.Correction{}
	actualSet, err := r.getRegistrarNameservers(&dc.Name)
	if err != nil {
		return nil, err
	}
	sort.Strings(actualSet)
	actual := strings.Join(actualSet, ",")

	expectedSet := []string{}
	for _, ns := range dc.Nameservers {
		expectedSet = append(expectedSet, ns.Name)
	}
	sort.Strings(expectedSet)
	expected := strings.Join(expectedSet, ",")

	if actual != expected {
		return []*models.Correction{
			{
				Msg: fmt.Sprintf("Update nameservers %s -> %s", actual, expected),
				F: func() error {
					_, err := r.updateRegistrarNameservers(dc.Name, expectedSet)
					return err
				},
			},
		}, nil
	}

	return corrections, nil
}

func (r *azureProvider) getRegistrarNameservers(domainName *string) ([]string, error) {
	var domainDetail *azured.GetDomainDetailOutput
	var err error
	withRetry(func() error {
		domainDetail, err = r.registrar.GetDomainDetail(&azured.GetDomainDetailInput{DomainName: domainName})
		return err
	})
	if err != nil {
		return nil, err
	}

	nameservers := []string{}
	for _, ns := range domainDetail.Nameservers {
		nameservers = append(nameservers, *ns.Name)
	}

	return nameservers, nil
}

func (r *azureProvider) updateRegistrarNameservers(domainName string, nameservers []string) (*string, error) {
	servers := []*azured.Nameserver{}
	for i := range nameservers {
		servers = append(servers, &azured.Nameserver{Name: &nameservers[i]})
	}
	var domainUpdate *azured.UpdateDomainNameserversOutput
	var err error
	withRetry(func() error {
		domainUpdate, err = r.registrar.UpdateDomainNameservers(&azured.UpdateDomainNameserversInput{
			DomainName: &domainName, Nameservers: servers})
		return err
	})
	if err != nil {
		return nil, err
	}

	return domainUpdate.OperationId, nil
}

func (r *azureProvider) fetchRecordSets(zoneID *string) ([]*azure.ResourceRecordSet, error) {
	if zoneID == nil || *zoneID == "" {
		return nil, nil
	}
	var next *string
	var nextType *string
	var records []*azure.ResourceRecordSet
	for {
		listInput := &azure.ListResourceRecordSetsInput{
			HostedZoneId:    zoneID,
			StartRecordName: next,
			StartRecordType: nextType,
			MaxItems:        sPtr("100"),
		}
		var list *azure.ListResourceRecordSetsOutput
		var err error
		withRetry(func() error {
			list, err = r.client.ListResourceRecordSets(listInput)
			return err
		})
		if err != nil {
			return nil, err
		}

		records = append(records, list.ResourceRecordSets...)
		if list.NextRecordName != nil {
			next = list.NextRecordName
			nextType = list.NextRecordType
		} else {
			break
		}
	}
	return records, nil
}

// we have to process names from azure to match what we expect and to remove their odd octal encoding
func unescape(s *string) string {
	if s == nil {
		return ""
	}
	name := strings.TrimSuffix(*s, ".")
	name = strings.Replace(name, `\052`, "*", -1) // TODO: escape all octal sequences
	return name
}

func (r *azureProvider) EnsureDomainExists(domain string) error {
	if _, ok := r.zones[domain]; ok {
		return nil
	}

	fmt.Printf("Adding zone for %s to Azure 53 account\n", domain)

	in := &azure.CreateHostedZoneInput{
		Name:            &domain,
		CallerReference: sPtr(fmt.Sprint(time.Now().UnixNano())),
	}
	var err error
	withRetry(func() error {
		_, err := r.client.CreateHostedZone(in)
		return err
	})
	return err
}
