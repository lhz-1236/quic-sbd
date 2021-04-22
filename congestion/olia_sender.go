package congestion

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)
const c_s =-0.01
const c_h = 0.3
const p_s = 0.1
const p_f = 0.1
const p_v = 0.7
const p_mad = 0.1
const p_d = 0.1
const p_l = 0.1

type OliaSender struct {
	hybridSlowStart HybridSlowStart
	prr             PrrSender
	rttStats        *RTTStats
	stats           connectionStats
	Olia            *Olia
	oliaSenders     map[protocol.PathID]*OliaSender
	Sbd_set         decision_set
	//******
	//  bs             map[int]map[protocol.PathID]*OliaSender
	//******
	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutbacks occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Congestion window in packets.
	congestionWindow protocol.PacketNumber

	// Slow start congestion window in packets, aka ssthresh.
	slowstartThreshold protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart bool

	// When true, texist slow start with large cutback of congestion window.
	slowStartLargeReduction bool

	// Minimum congestion window in packets.
	minCongestionWindow protocol.PacketNumber

	// Maximum number of outstanding packets for tcp.
	maxTCPCongestionWindow protocol.PacketNumber

	// Number of connections to simulate
	numConnections int

	// ACK counter for the Reno implementation
	congestionWindowCount protocol.ByteCount

	initialCongestionWindow    protocol.PacketNumber
	initialMaxCongestionWindow protocol.PacketNumber
}
//*****************
type decision_set struct {
	B    int
	Set  map[protocol.PathID]*OliaSender
	flag bool
}
//*****************


func NewOliaSender(oliaSenders map[protocol.PathID]*OliaSender, rttStats *RTTStats, initialCongestionWindow, initialMaxCongestionWindow protocol.PacketNumber) SendAlgorithmWithDebugInfo {
	return &OliaSender{
		rttStats:                   rttStats,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		minCongestionWindow:        defaultMinimumCongestionWindow,
		slowstartThreshold:         initialMaxCongestionWindow,
		maxTCPCongestionWindow:     initialMaxCongestionWindow,
		numConnections:             defaultNumConnections,
		Olia:                       NewOlia(0),
		oliaSenders:                oliaSenders,
	}
}

func (o *OliaSender) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	if o.InRecovery() {
		// PRR is used when in recovery.
		return o.prr.TimeUntilSend(o.GetCongestionWindow(), bytesInFlight, o.GetSlowStartThreshold())
	}
	if o.GetCongestionWindow() > bytesInFlight {
		return 0
	}
	return utils.InfDuration
}

func (o *OliaSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	// Only update bytesInFlight for data packets.
	if !isRetransmittable {
		return false
	}
	if o.InRecovery() {
		// PRR is used when in recovery.
		o.prr.OnPacketSent(bytes)
	}
	o.largestSentPacketNumber = packetNumber
	o.hybridSlowStart.OnPacketSent(packetNumber)
	return true
}

func (o *OliaSender) GetCongestionWindow() protocol.ByteCount {
	return protocol.ByteCount(o.congestionWindow) * protocol.DefaultTCPMSS
}

func (o *OliaSender) GetSlowStartThreshold() protocol.ByteCount {
	return protocol.ByteCount(o.slowstartThreshold) * protocol.DefaultTCPMSS
}

func (o *OliaSender) ExitSlowstart() {
	o.slowstartThreshold = o.congestionWindow
}

func (o *OliaSender) MaybeExitSlowStart() {
	if o.InSlowStart() && o.hybridSlowStart.ShouldExitSlowStart(o.rttStats.LatestRTT(), o.rttStats.MinRTT(), o.GetCongestionWindow()/protocol.DefaultTCPMSS) {
		o.ExitSlowstart()
	}
}

func (o *OliaSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := o.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := o.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstBytes
}

func getMaxCwnd(m map[protocol.PathID]*OliaSender) protocol.PacketNumber {
	var bestCwnd protocol.PacketNumber
	for _, os := range m {
		// TODO should we care about fast retransmit and RFC5681?
		bestCwnd = utils.MaxPacketNumber(bestCwnd, os.congestionWindow)
	}
	return bestCwnd
}

func getRate(m map[protocol.PathID]*OliaSender, pathRTT time.Duration) protocol.ByteCount {
	// We have to avoid a zero rate because it is used as a divisor
	var rate protocol.ByteCount = 1
	var tmpCwnd protocol.PacketNumber
	var scaledNum uint64
	for _, os := range m {
		tmpCwnd = os.congestionWindow
		scaledNum = oliaScale(uint64(tmpCwnd), scale) * uint64(pathRTT.Nanoseconds())
		if os.rttStats.SmoothedRTT() != time.Duration(0) {
			// XXX In MPTCP, we have an estimate of the RTT because of the handshake, not in QUIC...
			rate += protocol.ByteCount(scaledNum / uint64(os.rttStats.SmoothedRTT().Nanoseconds()))
		}
	}
	rate *= rate
	return rate
}

func (o *OliaSender) getEpsilon() {
	// TODOi
	var tmpRTT time.Duration
	var tmpBytes protocol.ByteCount

	var tmpCwnd protocol.PacketNumber

	var bestRTT time.Duration
	var bestBytes protocol.ByteCount

	var M uint8
	var BNotM uint8


	// TODO: integrate this in the following loop - we just want to iterate once
	maxCwnd := getMaxCwnd(o.oliaSenders)
	for _, os := range o.oliaSenders {
		tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
		tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
		if int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
			bestRTT = tmpRTT
			bestBytes = tmpBytes
		}
	}

	// TODO: integrate this here in getMaxCwnd and in the previous loop
	// Find the size of M and BNotM
	for _, os := range o.oliaSenders {
		tmpCwnd = os.congestionWindow
		if tmpCwnd == maxCwnd {
			M++
		} else {
			tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
			tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
			if int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
				BNotM++
			}
		}
	}

	// Check if the path is in M or BNotM and set the value of epsilon accordingly
	for _, os := range o.oliaSenders {
		if BNotM == 0 {
			os.Olia.epsilonNum = 0
			os.Olia.epsilonDen = 1
		} else {
			tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
			tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
			tmpCwnd = os.congestionWindow

			if tmpCwnd < maxCwnd && int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
				os.Olia.epsilonNum = 1
				os.Olia.epsilonDen = uint32(len(o.oliaSenders)) * uint32(BNotM)
			} else if tmpCwnd == maxCwnd {
				os.Olia.epsilonNum = -1
				os.Olia.epsilonDen = uint32(len(o.oliaSenders)) * uint32(M)
			} else {
				os.Olia.epsilonNum = 0
				os.Olia.epsilonDen = 1
			}
		}
	}
}
func (o *OliaSender) getEpsilon1(set map[protocol.PathID]*OliaSender) {
	// TODOi
	var tmpRTT time.Duration
	var tmpBytes protocol.ByteCount

	var tmpCwnd protocol.PacketNumber

	var bestRTT time.Duration
	var bestBytes protocol.ByteCount

	var M uint8
	var BNotM uint8

	// TODO: integrate this in the following loop - we just want to iterate once
	maxCwnd := getMaxCwnd(set)
	//fmt.Println("length of set:,",len(set))
	for _, os := range set {
		tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
		tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
		if int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
			bestRTT = tmpRTT
			bestBytes = tmpBytes
		}
	}

	// TODO: integrate this here in getMaxCwnd and in the previous loop
	// Find the size of M and BNotM
	for _, os := range set {
		tmpCwnd = os.congestionWindow
		if tmpCwnd == maxCwnd {
			M++
		} else {
			tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
			tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
			if int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
				BNotM++
			}
		}
	}

	// Check if the path is in M or BNotM and set the value of epsilon accordingly
	for _, os := range set {
		if BNotM == 0 {
			os.Olia.epsilonNum = 0
			os.Olia.epsilonDen = 1
		} else {
			tmpRTT = os.rttStats.SmoothedRTT() * os.rttStats.SmoothedRTT()
			tmpBytes = os.Olia.SmoothedBytesBetweenLosses()
			tmpCwnd = os.congestionWindow

			if tmpCwnd < maxCwnd && int64(tmpBytes) * bestRTT.Nanoseconds() >= int64(bestBytes) * tmpRTT.Nanoseconds() {
				os.Olia.epsilonNum = 1
				os.Olia.epsilonDen = uint32(len(set)) * uint32(BNotM)
			} else if tmpCwnd == maxCwnd {
				os.Olia.epsilonNum = -1
				os.Olia.epsilonDen = uint32(len(set)) * uint32(M)
			} else {
				os.Olia.epsilonNum = 0
				os.Olia.epsilonDen = 1
			}
		}
	}
}
func (o *OliaSender) maybeIncreaseCwnd(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, bytesInFlight protocol.ByteCount,owd time.Duration) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	//******
	var m map[protocol.PathID]*OliaSender
	if !o.isCwndLimited(bytesInFlight) {
		return
	}
	if o.congestionWindow >= o.maxTCPCongestionWindow {
		return
	}
	//********
	o.Olia.UpdateSbdVar(owd)
	//if o.Sbd_set.flag{
	//	m =o.Sbd_set.Set
	//}else{
		m =o.oliaSenders
	//}

  //********
	if o.InSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		o.congestionWindow++
		return
	} else {
		o.getEpsilon1(m)
		rate := getRate(m, o.rttStats.SmoothedRTT())
		cwndScaled := oliaScale(uint64(o.congestionWindow), scale)
		o.congestionWindow = utils.MinPacketNumber(o.maxTCPCongestionWindow, o.Olia.CongestionWindowAfterAck(o.congestionWindow, rate, cwndScaled))
	}
}

//*********************************
func sum(input []time.Duration) time.Duration{

	sum1 := time.Duration(0)
	for _, num :=range input{
		sum1 +=num
	}
	return sum1
}
func single1(o *Olia,pathid protocol.PathID){

	var OWD []time.Duration
	length :=0
	lenOfowd :=0
	for _,owd := range o.SBD.owd {
		//	fmt.Println(len(owd))
		if len(owd)>0{
			length++
			lenOfowd  += len(owd)
			//o.SBD.owd1 = append(o.SBD.owd1,sum(owd)/time.Duration(len(owd)))
			OWD = append(OWD,time.Duration(float64(sum(owd)/time.Nanosecond)/float64(len(owd))))
		}
	}
  o.SBD.owd1 = append(o.SBD.owd1,OWD[0])
	o.SBD.owd1 = append(o.SBD.owd1,OWD[:len(OWD)-1]...)
  var m time.Duration
	var dur time.Duration
	var n float64
	o.SBD.owd2 =time.Duration(float64(sum(o.SBD.owd1)/time.Nanosecond)/float64(length))
  for _,owd := range o.SBD.owd{
  	for j,i := range owd{
  		if j == 0{
  			m = i
  			continue
			}
			if (i-o.SBD.owd2)*(m-o.SBD.owd2)<time.Duration(0){
				n++
				dur += m-i
			}
			m = i
		}
	}
  o.SBD.count = n/50
  o.SBD.dur = time.Duration((float64(dur/time.Nanosecond))/n)
	//utils.Infof("skew_est:%f",o.SBD.skew_est)
	//utils.Infof("var_est:%s",o.SBD.var_est)
	//utils.Infof("freq_est:%f",o.SBD.freq_est)
	//utils.Infof("pac_loss:%f",o.SBD.pac_est)
}
func single(o *Olia,pathid protocol.PathID){
	var OWD []time.Duration
	length :=0
	lenOfowd :=0
	for _,owd := range o.SBD.owd {
		//	fmt.Println(len(owd))
		if len(owd)>0{
			length++
			lenOfowd  += len(owd)
			//o.SBD.owd1 = append(o.SBD.owd1,sum(owd)/time.Duration(len(owd)))
			OWD = append(OWD,time.Duration(float64(sum(owd)/time.Nanosecond)/float64(len(owd))))
			if length==0{
				o.SBD.owd1 = append(o.SBD.owd1,OWD[length])
			}else{
				o.SBD.owd1 = append(o.SBD.owd1,OWD[length-1])
			}
		}
	}
	//if len(OWD)==0{
	//	fmt.Println(o.SBD.owd)
	//}
	//o.SBD.owd1 = append(o.SBD.owd1,OWD[0])
	//o.SBD.owd1 = append(o.SBD.owd1,OWD[:len(OWD)-1]...)
	o.SBD.owd2 =time.Duration(float64(sum(o.SBD.owd1)/time.Nanosecond)/float64(length))
	var skew_base float64
	var var_base time.Duration
	i :=0
	for _,owd := range o.SBD.owd {
		if len(owd)>0{
			for _,v :=range owd{
				var_base += time.Duration(math.Abs(float64(v - o.SBD.owd1[i])))
				//var_base += time.Duration(math.Pow(float64(v - o.SBD.owd1[i]),2))
				if v < o.SBD.owd2{
					skew_base++
				}else if v > o.SBD.owd2{
					skew_base--
				}
			}
			i++
		}
	}
	if lenOfowd !=0{
		o.SBD.skew_est = skew_base/float64(lenOfowd)
		o.SBD.var_est = time.Duration(float64(var_base/time.Nanosecond)/float64(lenOfowd))
		o.SBD.pac_est = float64(o.SBD.Pac_loss1[1]-o.SBD.Pac_loss1[0])/float64(o.SBD.Pac_ack[1]-o.SBD.Pac_ack[0])


		for j :=0;j<len(o.SBD.owd1)-1;j++{
			if ((o.SBD.owd1[j]<(o.SBD.owd2-time.Duration(float64(p_v)*float64(o.SBD.var_est/time.Nanosecond))))&&(o.SBD.owd1[j+1]>(o.SBD.owd2+time.Duration(float64(p_v)*float64(o.SBD.var_est/time.Nanosecond)))))||
				((o.SBD.owd1[j+1]<(o.SBD.owd2-time.Duration(float64(p_v)*float64(o.SBD.var_est/time.Nanosecond))))&&(o.SBD.owd1[j]>(o.SBD.owd2+time.Duration(float64(p_v)*float64(o.SBD.var_est/time.Nanosecond))))){
				o.SBD.freq_est +=1/float64(len(o.SBD.owd1))
			}
		}
	}

	//utils.Infof("skew_est:%f",o.SBD.skew_est)
	//utils.Infof("var_est:%s",o.SBD.var_est)
	//utils.Infof("freq_est:%f",o.SBD.freq_est)
	//utils.Infof("pac_loss:%f",o.SBD.pac_est)
}

func (o *OliaSender) CalculateParameter(){
	for pathid, os := range o.oliaSenders{

			//fmt.Println(pathid)
			//for _,owd:= range os.Olia.SBD.owd{
			//	for _,m := range owd{
			//		fmt.Print(m)
			//	}
			//}
      //fmt.Println()
		single(os.Olia,pathid)
		//}
	}
	//o.oliaSenders[1].SaveData()
}
func (o *OliaSender) partition(G map[protocol.PathID]*OliaSender){
	var flag map[protocol.PathID]bool
	var group []protocol.PathID
	var set map[protocol.PathID]*OliaSender
	set = make(map[protocol.PathID]*OliaSender)
	flag = make(map[protocol.PathID]bool)
	for pathid,_ := range G{
		flag[pathid] = false
	}
	for pathid1,_ :=range G{
		if !flag[pathid1]{
			flag[pathid1]=true
			i :=0
			group = append(group, pathid1)
			for {
				if i==len(group){
					for _,id :=range group{
						set[id] = G[id]
					}
					for _,id :=range group{
						G[id].Sbd_set.Set = set
					}
					group = []protocol.PathID{}
					set = make(map[protocol.PathID]*OliaSender)
					break
				}else{
					pathid :=group[i]
					i++
					for pathid2, os2 :=range G{
						if !flag[pathid2]&&compare(G[pathid],os2){
							  flag[pathid2] = true
								group = append(group, pathid2)
						}
					}
				}
			}

		}
	}
	//var v time.Duration
	//var ploss float64
	//utils.Infof("len of G %d",len(G))
	//for _,os :=range G{
	//	for pathId1,os1 :=range G{
	//	//	utils.Infof("pathId %d",pathId1)
	//		if os.Olia.SBD.var_est<os1.Olia.SBD.var_est{
	//			v = os1.Olia.SBD.var_est
	//		}else {
	//			v = os.Olia.SBD.var_est
	//		}
	//		if os.Olia.SBD.pac_est<os1.Olia.SBD.pac_est{
	//			ploss = os1.Olia.SBD.pac_est
	//		}else {
	//			ploss = os.Olia.SBD.pac_est
	//		}
	//
	//		if (math.Abs(os.Olia.SBD.freq_est-os1.Olia.SBD.freq_est)<=p_f)&&
	//			(math.Abs(os.Olia.SBD.skew_est-os1.Olia.SBD.skew_est)<=p_s)&&
	//			(math.Abs(float64(os.Olia.SBD.var_est-os1.Olia.SBD.var_est))<=float64(time.Duration(10*p_mad*v)/10)){
	//
	//			if os.Olia.SBD.pac_est>p_l{
	//				if math.Abs(os.Olia.SBD.pac_est-os1.Olia.SBD.pac_est)<=p_d*ploss{
	//					os.Sbd_set.Set[pathId1]=os1
	//				}
	//			}else {
	//				  os.Sbd_set.Set[pathId1]=os1
	//			}

			//}
		//}
	//}
	//******

	//******
}
func compare1(first *OliaSender,second *OliaSender) bool{
	var v time.Duration
	var ploss float64

	if first.Olia.SBD.dur > second.Olia.SBD.dur {
		v = first.Olia.SBD.dur
	} else {
		v = second.Olia.SBD.dur
	}

	if (math.Abs(first.Olia.SBD.count-second.Olia.SBD.count) <= p_f*first.Olia.SBD.count) &&
		(math.Abs(float64(first.Olia.SBD.dur-second.Olia.SBD.dur)) <= float64(time.Duration(10*p_mad*v)/10)) {

		if ploss > p_l {
			if math.Abs(first.Olia.SBD.pac_est-second.Olia.SBD.pac_est) <= p_d*ploss {
				return true
			}
		} else {
			return true
		}
	}
	return false
}
func compare(first *OliaSender,second *OliaSender) bool{
	var v time.Duration
	var ploss float64

	if first.Olia.SBD.var_est > second.Olia.SBD.var_est {
		v = first.Olia.SBD.var_est
	} else {
		v = second.Olia.SBD.var_est
	}
	if first.Olia.SBD.pac_est > second.Olia.SBD.pac_est {
		ploss = first.Olia.SBD.pac_est
	} else {
		ploss = second.Olia.SBD.pac_est
	}

	if (math.Abs(first.Olia.SBD.freq_est-second.Olia.SBD.freq_est) <= p_f) &&
		(math.Abs(first.Olia.SBD.skew_est-second.Olia.SBD.skew_est) <= p_s) &&
		(math.Abs(float64(first.Olia.SBD.var_est-second.Olia.SBD.var_est)) <= float64(time.Duration(10*p_mad*v)/10)) {

		if ploss > p_l {
			if math.Abs(first.Olia.SBD.pac_est-second.Olia.SBD.pac_est) <= p_d*ploss {
				return true
			}
		} else {
			return true
		}
	}
	return false
}
func (o *OliaSender) clearSBD(){
	for _, os := range o.oliaSenders {
		os.Olia.SBD.Sbdcount = 0
		os.Olia.SBD.skew_est = 0
		os.Olia.SBD.freq_est = 0
		os.Olia.SBD.var_est = 0*time.Nanosecond
		os.Olia.SBD.pac_est = 0
		os.Olia.SBD.owd2 = 0*time.Nanosecond
		os.Olia.SBD.owd1 = []time.Duration{}
		os.Olia.SBD.owd = [50][]time.Duration{}
	}
}

func (o *OliaSender) SbdDecision(){

	var G map[protocol.PathID]*OliaSender = make(map[protocol.PathID]*OliaSender)
	for pathID, os := range o.oliaSenders {
		os.Sbd_set.flag = true
		os.Sbd_set.Set = make(map[protocol.PathID]*OliaSender)
		if (os.Olia.SBD.skew_est < c_s)||(os.Olia.SBD.skew_est < c_h&&os.Sbd_set.B==1)||(os.Olia.SBD.pac_est>p_l){
			os.Sbd_set.B = 1
			G[pathID] = os
		}else{
			os.Sbd_set.B = 0
		}
	}
	for _, os := range o.oliaSenders {
		if os.Sbd_set.B == 0 {
			for pathID1, os1 := range o.oliaSenders {
				if os1.Sbd_set.B == 0{
					os.Sbd_set.Set[pathID1] = os1
				}
			}
		}
	}
	o.partition(G)

	var Pathid []int
	for pathid,_:=range o.oliaSenders{
		Pathid = append(Pathid,int(pathid))
	}
	sort.Ints(Pathid)
	fmt.Printf("\n%-12s","pathid")
	for _,i := range Pathid{
		fmt.Printf("%-12d",i)
	}

  fmt.Printf("\n%-12s","skew_est")
	for _,i := range Pathid{
		fmt.Printf("%-12.4f",o.oliaSenders[protocol.PathID(i)].Olia.SBD.skew_est)
	}

	fmt.Printf("\n%-12s","var_est")
	for _,i := range Pathid{
		fmt.Printf("%-12s",o.oliaSenders[protocol.PathID(i)].Olia.SBD.var_est)
	}

	fmt.Printf("\n%-12s","freq_est")
	for _,i := range Pathid{
		fmt.Printf("%-12.4f",o.oliaSenders[protocol.PathID(i)].Olia.SBD.freq_est)
	}

	fmt.Printf("\n%-12s","pac_loss")
	for _,i := range Pathid{
		fmt.Printf("%-12f",o.oliaSenders[protocol.PathID(i)].Olia.SBD.pac_est)
	}

	fmt.Printf("\n%-12s","set")
	for _,i := range Pathid{
		fmt.Printf("%-12d",len(o.oliaSenders[protocol.PathID(i)].Sbd_set.Set))
	}
	fmt.Printf("\n%-12s","packet")
	//
	for _,i := range Pathid{

		fmt.Printf("%-12d",o.oliaSenders[protocol.PathID(i)].Olia.SBD.Pac_ack[1]-o.oliaSenders[protocol.PathID(i)].Olia.SBD.Pac_ack[0])

	}
	fmt.Println()
	//for _,i := range Pathid{
	//	fmt.Print(strconv.Itoa(i)+"ms")
	//	for _,owd:= range o.oliaSenders[protocol.PathID(i)].Olia.SBD.owd{
	//		for _,m := range owd{
	//			fmt.Print(m)
	//		}
	//	}
	//	fmt.Println()
	//}
	//fmt.Println("break")
	o.clearSBD()
}
func (o *OliaSender) Clearset(){
	for _,os :=range o.oliaSenders{
		os.Sbd_set.Set = make(map[protocol.PathID]*OliaSender)
	}
}
//*********************************
func (o *OliaSender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, bytesInFlight protocol.ByteCount,OWD time.Duration,count int,pac_loss uint64) {
	o.largestAckedPacketNumber = utils.MaxPacketNumber(ackedPacketNumber, o.largestAckedPacketNumber)

	if o.InRecovery() {
		// PRR is used when in recovery
		o.prr.OnPacketAcked(ackedBytes)
		return
	}
	o.Olia.UpdateAckedSinceLastLoss(ackedBytes)
	//o.Olia.UpdateSbdVar(OWD)
	//******
	o.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, bytesInFlight,OWD)
	if o.InSlowStart() {
		o.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (o *OliaSender) OnPacketLost(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, bytesInFlight protocol.ByteCount) {
	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= o.largestSentAtLastCutback {
		if o.lastCutbackExitedSlowstart {
			o.stats.slowstartPacketsLost++
			o.stats.slowstartBytesLost += lostBytes
			if o.slowStartLargeReduction {
				if o.stats.slowstartPacketsLost == 1 || (o.stats.slowstartBytesLost/protocol.DefaultTCPMSS) > (o.stats.slowstartBytesLost - lostBytes)/protocol.DefaultTCPMSS {
					// Reduce congestion window by 1 for every mss of bytes lost.
					o.congestionWindow = utils.MaxPacketNumber(o.congestionWindow-1, o.minCongestionWindow)
				}
				o.slowstartThreshold = o.congestionWindow
			}
		}
		return
	}
	o.lastCutbackExitedSlowstart = o.InSlowStart()
	if o.InSlowStart() {
		o.stats.slowstartPacketsLost++
	}

	o.prr.OnPacketLost(bytesInFlight)
	o.Olia.OnPacketLost()

	// TODO(chromium): Separate out all of slow start into a separate class.
	if o.slowStartLargeReduction && o.InSlowStart() {
		o.congestionWindow = o.congestionWindow - 1
	} else {
		o.congestionWindow = protocol.PacketNumber(float32(o.congestionWindow) * o.RenoBeta())
	}
	// Enforce a minimum congestion window.
	if o.congestionWindow < o.minCongestionWindow {
		o.congestionWindow = o.minCongestionWindow
	}
	o.slowstartThreshold = o.congestionWindow
	o.largestSentAtLastCutback = o.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	o.congestionWindowCount = 0
}

func (o *OliaSender) SetNumEmulatedConnections(n int) {
	o.numConnections = utils.Max(n, 1)
	// TODO should it be done also for OLIA?
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (o *OliaSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	o.largestSentAtLastCutback = 0
	if !packetsRetransmitted {
		return
	}
	o.hybridSlowStart.Restart()
	o.Olia.Reset()
	o.slowstartThreshold = o.congestionWindow / 2
	o.congestionWindow = o.minCongestionWindow
}

func (o *OliaSender) OnConnectionMigration() {
	o.hybridSlowStart.Restart()
	o.prr = PrrSender{}
	o.largestSentPacketNumber = 0
	o.largestAckedPacketNumber = 0
	o.largestSentAtLastCutback = 0
	o.lastCutbackExitedSlowstart = false
	o.Olia.Reset()
	o.congestionWindowCount = 0
	o.congestionWindow = o.initialCongestionWindow
	o.slowstartThreshold = o.initialMaxCongestionWindow
	o.maxTCPCongestionWindow = o.initialMaxCongestionWindow
	var c decision_set
	o.Sbd_set = c
}

// RetransmissionDelay gives the RTO retransmission time
func (o *OliaSender) RetransmissionDelay() time.Duration {
	if o.rttStats.SmoothedRTT() == 0 {
		return 0
	}
	return o.rttStats.SmoothedRTT() + o.rttStats.MeanDeviation() * 4
}

func (o *OliaSender) SmoothedRTT() time.Duration {
	return o.rttStats.SmoothedRTT()
}

func (o *OliaSender) SetSlowStartLargeReduction(enabled bool) {
	o.slowStartLargeReduction = enabled
}

func (o *OliaSender) BandwidthEstimate() Bandwidth {
	srtt := o.rttStats.SmoothedRTT()
	if srtt == 0 {
		// If we haven't measured an rtt, the bandwidth estimate is unknown.
		return 0
	}
	return BandwidthFromDelta(o.GetCongestionWindow(), srtt)
}

// HybridSlowStart returns the hybrid slow start instance for testing
func (o *OliaSender) HybridSlowStart() *HybridSlowStart {
	return &o.hybridSlowStart
}

func (o *OliaSender) SlowstartThreshold() protocol.PacketNumber {
	return o.slowstartThreshold
}

func (o *OliaSender) RenoBeta() float32 {
	// kNConnectionBeta is the backoff factor after loss for our N-connection
	// emulation, which emulates the effective backoff of an ensemble of N
	// TCP-Reno connections on a single loss event. The effective multiplier is
	// computed as:
	return (float32(o.numConnections) - 1. + renoBeta) / float32(o.numConnections)
}

func (o *OliaSender) InRecovery() bool {
	return o.largestAckedPacketNumber <= o.largestSentAtLastCutback && o.largestAckedPacketNumber != 0
}

func (o *OliaSender) InSlowStart() bool {
	return o.GetCongestionWindow() < o.GetSlowStartThreshold()
}