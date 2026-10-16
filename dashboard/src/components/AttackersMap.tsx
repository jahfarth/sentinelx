import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import { useApiData, fetchAttackers } from '../lib/api';
import { Spinner, ErrorBox, EmptyState } from './ui';

/** Circle radius grows with alert volume, clamped so the map stays readable. */
function markerRadius(alerts: number): number {
  return Math.max(7, Math.min(34, Math.sqrt(alerts) * 5));
}

export default function AttackersMap({ refreshKey }: { refreshKey: number }) {
  const { data, loading, error, reload } = useApiData(() => fetchAttackers(20), [refreshKey]);

  if (loading) {
    return (
      <div className="card span-12">
        <h3 className="card-title">Attacker Map</h3>
        <div style={{ height: 440, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Spinner />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card span-12">
        <h3 className="card-title">Attacker Map</h3>
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  const attackers = data?.attackers ?? [];

  return (
    <div className="card span-12">
      <h3 className="card-title">
        Attacker Map
        <span className="mono-sm">{attackers.length} source IPs</span>
      </h3>
      {attackers.length === 0 ? (
        <EmptyState message="No attackers yet — run the lab attacks." />
      ) : (
        <>
          <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={true} className="attackers-map">
            <TileLayer
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            />
            {attackers.map((a) => (
              <CircleMarker
                key={a.ip}
                center={[a.lat, a.lon]}
                radius={markerRadius(a.alerts)}
                pathOptions={{ color: '#ef4444', weight: 2, fillColor: '#ef4444', fillOpacity: 0.45 }}
              >
                <Popup>
                  <div className="mono-sm" style={{ fontSize: 13, color: '#e6ecf5' }}>
                    {a.ip}
                  </div>
                  <div style={{ marginTop: 4 }}>
                    {a.alerts} alert{a.alerts === 1 ? '' : 's'} · {a.country}
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
          <p className="map-note">
            SentinelX performs no external GeoIP lookup: coordinates are reported as 0,0 and
            private/loopback addresses are labelled "Private", so unlocated attackers cluster
            off the west coast of Africa.
          </p>
        </>
      )}
    </div>
  );
}
